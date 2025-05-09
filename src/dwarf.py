import logging
import os
import re

from angr import PointerWrapper
import claripy
from elftools.dwarf.callframe import CIE, FDE, ZERO, instruction_name
from elftools.dwarf.descriptions import describe_attr_value
from elftools.elf.elffile import ELFFile

log = logging.getLogger(__name__)

class ELFDwarf(object):
    """An abstraction of ELF Dwarf debug symbols."""

    re_dw_op_fbreg = re.compile('DW_OP_fbreg: (-?[0-9]+)')

    # parsing DWARF is expensive, so we want to cache what we can

    def __init__(self, filepath):
        self.cache_addr2func = dict()
        self.cache_func2vars = dict()
        self.bin_path = filepath
        self.bin_fd = open(self.bin_path, 'rb')
        self.elf = ELFFile(self.bin_fd)

        if not self.elf.has_dwarf_info():
            raise ValueError("%s has no DWARF debug info" %
                    os.path.basename(self.bin_path))

        self.dwarf_info = self.elf.get_dwarf_info()

    def get_local_var_locs(self, state):
        """Find the locations of all local variables for a given angr state.

        Keyword Arguments:
        state -- The angr state.

        Returns:
        A dictionary mapping variable names to absolute virtual addresses, or
        None if an error occured.
        """
        #print(self.cache_func2vars)
        if state.addr == 0:
            # state just returned from target function
            addr = state.history.bbl_addrs[-1]
        else:
            addr = state.addr

        # we'll store the results here
        func_vars = dict()

        # first, we need to know which function we're in
        if addr in self.cache_addr2func:
            # cache hit
            func_die = self.cache_addr2func[addr]
            #print("FUNC_DIE from cache!!! " + str(func_die))
        else:
            # cache miss
            rva = self._ava2rva(state, addr)
            if rva is None:
                log.error("Failed to find function containing %#x" % addr)
                return None
            func_die = self._find_func(rva)
            #print("FUNC_DIE NOOOTT from cache!!! " + str(func_die))
            if func_die is None:
                log.error("Function at RVA %#x has no DWARF debug info" % rva)
                return None

            self.cache_addr2func[addr] = func_die

        if func_die in self.cache_func2vars:
            # cache hit
            return self.cache_func2vars[func_die]

        # this attribute describes how the frame base is calculated, which we
        # need for computing local variable addresses that are relative to this
        # frame base
        func_fbase = func_die.attributes['DW_AT_frame_base']
        func_fbase_type = describe_attr_value(
                func_fbase,
                func_die,
                func_die.offset)

        # calculate the address of the frame base
        fbase_ava = self._frame_base_ava(state, func_fbase_type)
        if fbase_ava is None:
            log.error("Failed to find frame base address")
            return None

        for ch in func_die.iter_children():
            if ch.tag != 'DW_TAG_variable':
                # we only care about local variables
                continue

            var_name = ch.attributes['DW_AT_name'].value.decode('utf8')
            var_loc = ch.attributes['DW_AT_location']
            var_str = describe_attr_value(var_loc, ch, ch.offset)

            # parse the type of location and important values
            res = self.re_dw_op_fbreg.search(var_str)
            if res:
                # DW_OP_fbreg
                offset = int(res.groups()[0])
                log.debug("DW_OP_fbreg: %s %#x" % (var_name, offset))
                var_ava = fbase_ava + offset

                func_vars[var_name] = var_ava

        # update cache for faster lookups in the future
        self.cache_func2vars[func_die] = func_vars
        return func_vars

    def _frame_base_ava(self, state, fbtype):
        """Calculates the absolute virtual address of the current frame base."""
        if state.addr == 0:
            # state just returned from target function
            addr = state.history.bbl_addrs[-1]
        else:
            addr = state.addr

        if '(DW_OP_call_frame_cfa)' in fbtype:
            # DW_OP_call_frame_cfa
            rva = self._ava2rva(state, addr)
            if rva is None:
                log.error("Failed to find function address: %#x" % addr)
                return None

            # find the frame
            frame = self._find_frame(rva)
            if frame is None:
                log.error("Cannot find frame for address: %#x" % addr)
                return None

            # interpret instructions to get frame base
            #
            # This is a pretty complicated step because the virtual machine
            # defined in DWARF is designed to handle all sorts of nonsense, but
            # because we know the code we're dealing with is GCC compiled for
            # X86_64 Linux with debug symbols, we can cheat doing a proper
            # emulation and probably get the correct result.
            cfa_offsets = set()
            for insn in frame.instructions:
                name = instruction_name(insn.opcode)

                if name == 'DW_CFA_def_cfa_offset':
                    cfa_offsets.add(insn.args[0])

            if len(cfa_offsets) < 1:
                log.error("Failed to find CFA offset")
                return None
            elif len(cfa_offsets) > 1:
                log.warning("CFA offset moves during function execution,"
                        " using any offset.")

            cfa_offset = list(cfa_offsets)[0]
            log.debug("cfa_offset: %#x" % cfa_offset)

            return state.solver.eval(state.regs.rbp) + cfa_offset

        elif '(DW_OP_reg6 (r6))' in fbtype:
            # all offsets are relative to RBP
            return state.solver.eval(state.regs.rbp)

        else:
            log.error("Unhandled DW_AT_frame_base: %s" % fbtype)
            return None

    def _iter_frames(self, rva, iter):
        for CFI in iter:
            if not isinstance(CFI, FDE):
                # we don't care about CIE or ZERO
                continue

            low_pc = CFI['initial_location']
            high_pc = low_pc + CFI['address_range']

            if rva >= low_pc and rva < high_pc:
                return CFI

        return None

    def _find_frame(self, rva):
        """Finds the frame associated with a relative virtual address."""
        if self.dwarf_info.has_EH_CFI():
            frame = self._iter_frames(rva, self.dwarf_info.EH_CFI_entries())
            if not frame is None:
                return frame

        if self.dwarf_info.has_CFI():
            frame = self._iter_frames(rva, self.dwarf_info.CFI_entries())
            if not frame is None:
                return frame

        return None

    def _ava2rva(self, state, addr):
        """Convert an absolute virtual address to relative."""
        ldr = state.project.loader
        obj = ldr.find_object_containing(addr)
        if obj is None:
            log.error("Address %#x doesn't belong to an object" % addr)
            return None

        return addr - obj.mapped_base

    def _find_func(self, ident):
        """Finds a function's DIE in the debug info.

        Keyword Arguments:
        ident -- Either the name of the function, or an address within it.

        Returns:
        A DIE, or None if the function could not be found.
        """
        if isinstance(ident, str):
            ident = ident.encode('utf8')

        for CU in self.dwarf_info.iter_CUs():
            for DIE in CU.iter_DIEs():
                if DIE.tag != 'DW_TAG_subprogram':
                    # we're looking for a function
                    continue

                if isinstance(ident, bytes):
                    #print("IDENTBYTE: " + str(ident))
                    if DIE.attributes['DW_AT_name'].value == ident:
                        return DIE
                elif isinstance(ident, int):
                    #print("IDENTINT: " + str(ident))
                    if 'DW_AT_low_pc' not in DIE.attributes or 'DW_AT_high_pc' not in DIE.attributes:
                        continue 
                    min_pc = DIE.attributes['DW_AT_low_pc'].value
                    max_pc = min_pc + DIE.attributes['DW_AT_high_pc'].value
                    if ident >= min_pc and ident < max_pc:
                        return DIE

        log.error("Failed to find DIE for: %s" % ident)
        return None
