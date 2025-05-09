
from datetime import datetime
import logging

import angr
from angr.analyses.decompiler.structured_codegen.c import CVariable
from angr.sim_variable import *
from angr.sim_type import *

import dwarf
from collections import OrderedDict
from IPython  import embed
import os

import claripy

log = logging.getLogger(__name__)

def compare_bvs(self, o_state, o_solver, o_bv, r_state, r_solver, r_bv, c_name):
    """Compares two bitvectors.

    Returns:
    True if they're equivalent, otherwise False.
    """

    self.metrics.total_var_comparison += 1
    if id(o_state) in self.cache_ostate_value.keys():

        ostate_val_dict = self.cache_ostate_value[id(o_state)]
        if c_name in ostate_val_dict.keys():
            o_min, o_max = ostate_val_dict[c_name]
            log.debug("[Cache] o_min: %#x" % o_min)
            log.debug("[Cache] o_max: %#x" % o_max)
        else:
            o_min = o_solver.min(o_bv)
            log.debug("[Eval] *o_min: %#x" % o_min)
            o_max = o_solver.max(o_bv)
            log.debug("[Eval] *o_max: %#x" % o_max)
            temp_dict = self.cache_ostate_value[id(o_state)]
            temp_dict[c_name] = (o_min,o_max)
            

    else:
        o_min = o_solver.min(o_bv)
        log.debug("[Eval] **o_min: %#x" % o_min)
        o_max = o_solver.max(o_bv)
        log.debug("[Eval] **o_max: %#x" % o_max)
        temp_dict = {c_name:(o_min,o_max)}
        self.cache_ostate_value[id(o_state)] = temp_dict


    if id(r_state) in self.cache_rstate_value.keys():

        rstate_val_dict = self.cache_rstate_value[id(r_state)]
        if c_name in rstate_val_dict.keys():
            r_min, r_max = rstate_val_dict[c_name]
            log.debug("[Cache] r_min: %#x" % r_min)
            log.debug("[Cache] r_max: %#x" % r_max)
        else:
            r_min = r_solver.min(r_bv)
            log.debug("[Eval] *r_min: %#x" % r_min)
            r_max = r_solver.max(r_bv)
            log.debug("[Eval] *r_max: %#x" % r_max)
            temp_dict = self.cache_rstate_value[id(r_state)]
            temp_dict[c_name] = (r_min,r_max)

    else:
        r_min = r_solver.min(r_bv)
        log.debug("[Eval] **r_min: %#x" % r_min)
        r_max = r_solver.max(r_bv)
        log.debug("[Eval] **r_max: %#x" % r_max)
        temp_dict = {c_name:(r_min,r_max)}
        self.cache_rstate_value[id(r_state)] = temp_dict

    if o_min == r_min and o_max == r_max:
        return True

    return False

def compare_bvs_basic(self, o_state, o_solver, o_bv, r_state, r_solver, r_bv):

    o_min = o_solver.min(o_bv)
    log.debug("[Basic] o_min: %#x" % o_min)
    o_max = o_solver.max(o_bv)
    log.debug("[Basic] o_max: %#x" % o_max)

    r_min = r_solver.min(r_bv)
    log.debug("[Basic] r_min: %#x" % r_min)
    r_max = r_solver.max(r_bv)
    log.debug("[Basic] r_max: %#x" % r_max)

    if o_min == r_min and o_max == r_max:
        return True

    return False

class VariableDiff(object):
    """A variable diff captures the value of a variable between two different
    states. For example, one state may be from one implementation of a function
    and the other state may be from another function that is suppose to be
    equivalent."""

    def __init__(self, cvar, aval, bval, asolver, bsolver, astate, bstate):
        """Initialize the object.

        Keyword Arguments:
        cvar -- The CVariable for this variable.
        aval -- The bitvector from the first state.
        bval -- The bitvector from the second state.
        asolver -- The solver for the first state.
        bsolver -- The solver for the second state.
        """
        self.cvar = cvar
        self.vals = [aval, bval]
        self.solvers = [asolver, bsolver]
        self.states = [astate, bstate]

class SymbolicDifferentialAnalysis(object):
    """A manager for performing differential analysis between two binary
    versions of the same function, one of which is a recompilation of the
    decompilation of the other."""

    def __init__(self, bin_name, orig_proj, orig_cfg, decomp, func, fp_new_bin, 
                dec_type, dec_dir, start_time, metrics):
        """Initialize a symbolic differential analysis manager.

        Keyword Arguments:
        orig_proj -- An angr Project for the original binary.
        orig_cfg -- An angr CFG for the original binary.
        decomp -- The angr Decompiler for the target function.
        fp_new_bin -- Filepath to the new binary containing the recompiled
        version of the target function.
        """
        self.cache_ostate_value = dict()
        self.cache_rstate_value = dict() 

        self.bin_name = bin_name
        self.orig_project = orig_proj
        self.orig_cfg = orig_cfg
        self.orig_decomp = decomp
        self.orig_func = func
        self.recomp_bin_fp = fp_new_bin
        self.dec_type = dec_type
        self.start_time = start_time
        self.metrics = metrics

        if dec_type == "Angr":
            self.angr_dir = dec_dir
        elif dec_type == "Ghidra":
            self.gh_dir = dec_dir
        elif dec_type == "Ida":
            self.ida_dir = dec_dir

        log.info("Creating project and CFG for: %s" % fp_new_bin)

        self.recomp_project = angr.Project(
                self.recomp_bin_fp,
                auto_load_libs=False,
                load_debug_info=True,
                main_opts={"base_addr": 0x400000}
        )

        self.recomp_cfg = self.recomp_project.analyses.CFGFast(
                binary=self.recomp_project.loader.main_object,
                objects=[self.recomp_project.loader.main_object],
                cross_references=True,
                normalize=True,
                show_progressbar=False
        )

        self.recomp_project.analyses.CompleteCallingConventions(recover_variables=True)
        self.recomp_cfg.project.analyses.CompleteCallingConventions(recover_variables=True)


        # new function should have same name as original and its name should be
        # known from the binary because we compiled with debug symbols
        self.recomp_func = self.recomp_cfg.functions.function(
                name=self.orig_func.name)

        if self.recomp_func is None:
            raise Exception("Could not get recompiled function from angr CFG")

        # starting states for analysis
        self.sim_opts = {angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                         angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}

        self.orig_init_state = self.orig_project.factory.call_state(
                self.orig_func.addr,
                prototype=self.orig_func.prototype,
                ret_addr=0,
                add_options=self.sim_opts
        )

        # using the prototype from the original function is intentional, these
        # functions are suppose to be the same!
        self.recomp_init_state = self.recomp_project.factory.call_state(
                self.recomp_func.addr,
                prototype=self.orig_func.prototype,
                ret_addr=0,
                add_options=self.sim_opts
        )
        if self.dec_type == "Ida":
            self.recomp_dwarf = dwarf.ELFDwarf(self.recomp_bin_fp)
        else:
            self.recomp_dwarf = dwarf.ELFDwarf(self.recomp_bin_fp)

    def compare_states(self, orig_state, recomp_state):
        """Compare a state from the original binary against a state from the
        recompiled binary.

        Keyword Arguments:
        orig_state -- State from original binary.
        recomp_state -- State from the recompiled binary.

        Returns:
        A tuple. The first value is True if the states are considered
        equivalent, otherwise it is False. The second value is a VariableDiff
        when the states are not equivalent, capturing the variable that makes
        the two states different.
        """

        self.metrics.total_state_comparison += 1
        any_comparison = False
        if self.dec_type == "Ida":

            o_solver = orig_state.solver
            r_solver = recomp_state.solver

            # orig and recomp local variables
            recomp_vars = self.recomp_dwarf.get_local_var_locs(recomp_state)

            local_vars = []

            with open(os.path.join(self.ida_dir, "non-ptr_vars.l"), "r") as f2:
                lines = f2.readlines()
                for line in lines:
                    line = line.replace("\n", "")
                    name, offset, size, is_ptr, ptr_size = line.split(";")
                    local_vars.append((name, int(offset), int(size), int(is_ptr), int(ptr_size)))

            # compare local variables
            cmp_vars = set()
            for c_name, offset, size, is_ptr, ptr_size in local_vars:

                if c_name in cmp_vars:
                    # already compared this variable
                    continue
                else:
                    cmp_vars.add(c_name)

                if not c_name in recomp_vars:
                    log.warning("Failed to find debug info for: %s" % c_name)
                    continue

                log.debug("\n#######################################################################")
                if is_ptr:
                    r_addr = recomp_vars[c_name]
                    recomp_ptr_val = recomp_state.memory.load(r_addr, ptr_size, endness=recomp_state.arch.memory_endness)
                    if recomp_ptr_val.uninitialized:
                        r_val = claripy.BVS("uninit_ptr1", recomp_state.arch.bits)
                    else:
                        try:
                            res = recomp_state.solver.eval_atleast(recomp_ptr_val, 2)

                        except angr.errors.SimValueError:
                            res = recomp_state.solver.eval_atleast(recomp_ptr_val, 1)
                        
                        if len(res) > 1:
                            r_val = claripy.BVS("uninit_ptr2", recomp_state.arch.bits)

                        elif len(res) == 1:
                            if res[0] == 0:
                                r_val = claripy.BVS("uninit_ptr3", recomp_state.arch.bits)
                            else:
                                r_val = recomp_state.memory.load(recomp_state.solver.eval(recomp_ptr_val), size, endness=recomp_state.arch.memory_endness)

                        else:
                            log.debug("In pointer handling: It should not reach to this point!!")
                            raise Exception("In pointer handling: It should not reach to this point!!")

                    log.debug("R_ptr_addr: " + str(r_addr) + " -- R_ptr_size: " + str(ptr_size) + " -- R_ptr_val: " + str(recomp_ptr_val) + " -- R_ptr_uninit: " + str(recomp_ptr_val.uninitialized))
                    log.debug("R_addr: " + str(recomp_state.solver.eval(recomp_ptr_val)) + " -- R_size: " + str(size) + " -- R_val: " + str(r_val))

                    o_base = orig_state.regs.rbp
                    o_addr = offset + o_solver.eval(o_base)
                    orig_ptr_val = orig_state.memory.load(o_addr, ptr_size, endness=orig_state.arch.memory_endness)

                    if orig_ptr_val.uninitialized:
                        o_val = claripy.BVS("uninit_ptr1", orig_state.arch.bits)
                    else:
                        try:
                            res = orig_state.solver.eval_atleast(orig_ptr_val, 2)
                        except angr.errors.SimValueError:
                            res = orig_state.solver.eval_atleast(orig_ptr_val, 1)
                        
                        if len(res) > 1:
                            o_val = claripy.BVS("uninit_ptr2", orig_state.arch.bits)

                        elif len(res) == 1:
                            if res[0] == 0:
                                o_val = claripy.BVS("uninit_ptr3", orig_state.arch.bits)
                            else:
                                o_val = orig_state.memory.load(orig_state.solver.eval(orig_ptr_val), size, endness=orig_state.arch.memory_endness)
                        else:
                            log.debug("In pointer handling: It should not reach to this point!!")
                            raise Exception("In pointer handling: It should not reach to this point!!")
                    
                    log.debug("O_base: " + str(o_base) + " -- Offset: " + str(offset))
                    log.debug("O_ptr_addr: " + str(o_addr) + " -- O_ptr_size: " + str(ptr_size) + " -- O_ptr_val: " + str(orig_ptr_val) + " -- O_ptr_uninit: " + str(orig_ptr_val.uninitialized))
                    log.debug("O_addr: " + str(orig_state.solver.eval(orig_ptr_val)) + " -- O_size: " + str(size) + " -- O_val: " + str(o_val))

                    log.debug("O_state: " + str(orig_state) + " -- R_state: " + str(recomp_state))

                else:
                    r_addr = recomp_vars[c_name]
                    r_val = recomp_state.memory.load(r_addr, size, endness=recomp_state.arch.memory_endness)
                    log.debug("R_addr: " + str(r_addr) + " -- R_size: " + str(size) + " -- R_val: " + str(r_val))

                    o_base = orig_state.regs.rbp
                    o_addr = offset + o_solver.eval(o_base)
                    o_val = orig_state.memory.load(o_addr, size, endness=orig_state.arch.memory_endness)

                    log.debug("O_base: " + str(o_base) + " -- Offset: " + str(offset))
                    log.debug("O_addr: " + str(o_addr) + " -- O_size: " + str(size) + " -- O_val: " + str(o_val))

                    log.debug("O_state: " + str(orig_state) + " -- R_state: " + str(recomp_state))

                log.info("Comparing %s" % (c_name))
                log.debug("IDA - Comparing %s: %s vs. %s" % (c_name, str(o_val), str(r_val)))
                if not any_comparison:
                    any_comparison = True
                if not compare_bvs(self, orig_state, o_solver, o_val, recomp_state, r_solver, r_val, c_name):
                    self.metrics.real_state_comparison += 1
                    return (False, VariableDiff(c_name, o_val, r_val, o_solver, r_solver, orig_state, recomp_state))

            # all comparisons matched
            if any_comparison:
                self.metrics.real_state_comparison += 1
            return (True, None)

        elif self.dec_type == "Angr":
            o_solver = orig_state.solver
            r_solver = recomp_state.solver

            # orig and recomp local variables
            recomp_vars = self.recomp_dwarf.get_local_var_locs(recomp_state)
            local_vars = self.orig_decomp.codegen.cfunc.variables_in_use
            # compare local variables
            cmp_vars = set()
            for simvar, cvar in local_vars.items():
                if not isinstance(cvar, CVariable):
                    continue

                c_name = cvar.c_repr()
                if c_name in cmp_vars:
                    # already compared this variable
                    continue
                else:
                    cmp_vars.add(c_name)

                if isinstance(simvar, SimRegisterVariable):
                    # don't worry about registers, wait until the variable is
                    # committed to memory
                    pass
                elif isinstance(simvar, SimMemoryVariable):
                    if not c_name in recomp_vars:
                        log.warning("Failed to find debug info for: %s" % c_name)
                        continue

                    if isinstance(cvar.variable_type, SimTypePointer):
                        r_addr = recomp_vars[c_name]
                        recomp_ptr_val = recomp_state.memory.load(r_addr, cvar.type.size // 8, endness=recomp_state.arch.memory_endness)

                        if recomp_ptr_val.uninitialized:
                            r_val = claripy.BVS("uninit_ptr1", recomp_state.arch.bits)
                        else:
                            try:
                                res = recomp_state.solver.eval_atleast(recomp_ptr_val, 2)

                            except angr.errors.SimValueError:
                                res = recomp_state.solver.eval_atleast(recomp_ptr_val, 1)
                            
                            if len(res) > 1:
                                r_val = claripy.BVS("uninit_ptr2", recomp_state.arch.bits)

                            elif len(res) == 1:
                                if res[0] == 0:
                                    r_val = claripy.BVS("uninit_ptr3", recomp_state.arch.bits)
                                else:
                                    r_val = recomp_state.memory.load(r_solver.eval(recomp_ptr_val), cvar.type.size // 8, endness=recomp_state.arch.memory_endness)
                            else:
                                log.debug("In pointer handling: It should not reach to this point!!")
                                raise Exception("In pointer handling: It should not reach to this point!!")

                        # orig memory variable
                        if isinstance(simvar, SimStackVariable):
                            o_base = getattr(orig_state.regs, simvar.base)
                            o_addr = simvar.offset + o_solver.eval(o_base) + 8
                        else:
                            o_addr = simvar.addr
                        orig_ptr_val = orig_state.memory.load(o_addr, cvar.type.size // 8, endness=orig_state.arch.memory_endness)

                        if orig_ptr_val.uninitialized:
                            o_val = claripy.BVS("uninit_ptr1", orig_state.arch.bits)
                        else:
                            try:
                                res = orig_state.solver.eval_atleast(orig_ptr_val, 2)
                            except angr.errors.SimValueError:
                                res = orig_state.solver.eval_atleast(orig_ptr_val, 1)
                            
                            if len(res) > 1:
                                o_val = claripy.BVS("uninit_ptr2", orig_state.arch.bits)

                            elif len(res) == 1:
                                if res[0] == 0:
                                    o_val = claripy.BVS("uninit_ptr3", orig_state.arch.bits)
                                else:
                                    o_val = orig_state.memory.load(o_solver.eval(orig_ptr_val), cvar.type.size // 8, endness=orig_state.arch.memory_endness)
                            else:
                                log.debug("In pointer handling: It should not reach to this point!!")
                                raise Exception("In pointer handling: It should not reach to this point!!")
                        log.debug("O_state: " + str(orig_state) + " -- R_state: " + str(recomp_state))

                    else:
                        # recomp memory variable
                        r_addr = recomp_vars[c_name]
                        r_val = recomp_state.memory.load(r_addr, cvar.type.size // 8, endness=recomp_state.arch.memory_endness)

                        # orig memory variable
                        if isinstance(simvar, SimStackVariable):
                            o_base = getattr(orig_state.regs, simvar.base)
                            o_addr = simvar.offset + o_solver.eval(o_base) + 8
                        else:
                            o_addr = simvar.addr
                        o_val = orig_state.memory.load(o_addr, cvar.type.size // 8, endness=orig_state.arch.memory_endness)
                        log.debug("O_state: " + str(orig_state) + " -- R_state: " + str(recomp_state))

                    log.info("Comparing %s" % (c_name))
                    log.debug("Angr - Comparing %s: %s vs. %s" % (c_name, str(o_val), str(r_val)))
                    if not any_comparison:
                        any_comparison = True
                    if not compare_bvs(self, orig_state, o_solver, o_val, recomp_state, r_solver, r_val, c_name):
                        self.metrics.real_state_comparison += 1
                        return (False, VariableDiff(c_name, o_val, r_val, o_solver, r_solver, orig_state, recomp_state))

                else:
                    log.warning("Unhandled SimVariable: %s" % str(simvar))

            # all comparisons matched
            if any_comparison:
                self.metrics.real_state_comparison += 1
            return (True, None)
        
        elif self.dec_type == "Ghidra":

            o_solver = orig_state.solver
            r_solver = recomp_state.solver

            #Get orig and recomp local variables
            recomp_vars = self.recomp_dwarf.get_local_var_locs(recomp_state)

            local_vars = []
            with open(os.path.join(self.gh_dir, "vardefs.l"), "r") as f2:
                lines = f2.readlines()
                for line in lines:
                    line = line.replace("\n", "")
                    name, offset, size, is_ptr, ptr_size = line.split(";")
                    local_vars.append((name, int(offset), int(size), int(is_ptr), int(ptr_size)))

            # compare local variables
            cmp_vars = set()
            for c_name, offset, size, is_ptr, ptr_size in local_vars:

                if c_name in cmp_vars:
                    # already compared this variable
                    continue
                else:
                    cmp_vars.add(c_name)

                if not c_name in recomp_vars:
                    log.warning("Failed to find debug info for: %s" % c_name)
                    continue

                if is_ptr:
                    r_addr = recomp_vars[c_name]
                    recomp_ptr_val = recomp_state.memory.load(r_addr, ptr_size, endness=recomp_state.arch.memory_endness)
                    r_val = recomp_state.memory.load(recomp_state.solver.eval(recomp_ptr_val), size, endness=recomp_state.arch.memory_endness)

                    if recomp_ptr_val.uninitialized:
                        r_val = claripy.BVS("uninit_ptr1", recomp_state.arch.bits)
                    else:
                        try:
                            res = recomp_state.solver.eval_atleast(recomp_ptr_val, 2)

                        except angr.errors.SimValueError:
                            res = recomp_state.solver.eval_atleast(recomp_ptr_val, 1)
                        
                        if len(res) > 1:
                            r_val = claripy.BVS("uninit_ptr2", recomp_state.arch.bits)

                        elif len(res) == 1:
                            if res[0] == 0:
                                r_val = claripy.BVS("uninit_ptr3", recomp_state.arch.bits)
                            else:
                                r_val = recomp_state.memory.load(recomp_state.solver.eval(recomp_ptr_val), size, endness=recomp_state.arch.memory_endness)
                        else:
                            log.debug("In pointer handling: It should not reach to this point!!")
                            raise Exception("In pointer handling: It should not reach to this point!!")

                    o_base = orig_state.regs.rbp
                    o_addr = offset + o_solver.eval(o_base)
                    orig_ptr_val = orig_state.memory.load(o_addr, ptr_size, endness=orig_state.arch.memory_endness)
                    o_val = orig_state.memory.load(orig_state.solver.eval(orig_ptr_val), size, endness=orig_state.arch.memory_endness)

                    if orig_ptr_val.uninitialized:
                        o_val = claripy.BVS("uninit_ptr1", orig_state.arch.bits)
                    else:
                        try:
                            res = orig_state.solver.eval_atleast(orig_ptr_val, 2)
                        except angr.errors.SimValueError:
                            res = orig_state.solver.eval_atleast(orig_ptr_val, 1)
                        
                        if len(res) > 1:
                            o_val = claripy.BVS("uninit_ptr2", orig_state.arch.bits)

                        elif len(res) == 1:
                            if res[0] == 0:
                                o_val = claripy.BVS("uninit_ptr3", orig_state.arch.bits)
                            else:
                                o_val = orig_state.memory.load(orig_state.solver.eval(orig_ptr_val), size, endness=orig_state.arch.memory_endness)
                        else:
                            log.debug("In pointer handling: It should not reach to this point!!")
                            raise Exception("In pointer handling: It should not reach to this point!!")

                    log.debug("O_base: " + str(o_base) + " Offset: " + str(offset) + " Ptr_val: " + str(orig_ptr_val) + " Ptr_size: " + str(ptr_size) + " Ptr_size: " + str(orig_ptr_val))
                    log.debug("O_addr: " + str(orig_state.solver.eval(orig_ptr_val)) + " O_val: " + str(o_val))
                    log.debug("O_state: " + str(orig_state) + " R_state: " + str(recomp_state))
                    
                else:
                    r_addr = recomp_vars[c_name]
                    r_val = recomp_state.memory.load(r_addr, size, endness=recomp_state.arch.memory_endness)

                    o_base = orig_state.regs.rbp
                    o_addr = offset + o_solver.eval(o_base)
                    o_val = orig_state.memory.load(o_addr, size, endness=orig_state.arch.memory_endness)

                    log.debug("R_addr: " + str(r_addr) + " R_value: " + str(r_val))
                    log.debug("O_base: " + str(o_base) + " Offset: " + str(offset) + " O_addr: " + str(o_addr) + " Size: " + str(size) + " O_val: " + str(o_val))
                    log.debug("O_state: " + str(orig_state) + " R_state: " + str(recomp_state))

                log.info("Comparing %s" % (c_name))
                log.debug("Ghidra - Comparing %s: %s vs. %s" % (c_name, str(o_val), str(r_val)))

                if not any_comparison:
                    any_comparison = True
                if not compare_bvs(self, orig_state, o_solver, o_val, recomp_state, r_solver, r_val, c_name):
                    self.metrics.real_state_comparison += 1
                    return (False, VariableDiff(c_name, o_val, r_val, o_solver, r_solver, orig_state, recomp_state))

            # all comparisons matched
            if any_comparison:
                self.metrics.real_state_comparison += 1
            return (True, None)

    def analyze(self, func, dec_type, max_steps=None):
        """Run the differential analysis between the two binary functions.

        Keyword Arguments:
        max_steps -- Optional maximum number of steps to compare functions over.
        """
        # create a simulation manager for each function
        orig_smgr = angr.SimulationManager(
                self.orig_project,
                active_states=[self.orig_init_state.copy()]
        )
        recomp_smgr = angr.SimulationManager(
                self.recomp_project,
                active_states=[self.recomp_init_state.copy()]
        )

        # we use this list throughout the code to mirror operations across both
        # simulation managers
        smgrs = [orig_smgr, recomp_smgr]
        log.info("Number of basic blocks: Orig: %d - Recomp: %d" % (len(self.orig_func.block_addrs), len(self.recomp_func.block_addrs)))
        self.metrics.o_bblocks = len(self.orig_func.block_addrs)
        self.metrics.r_bblocks = len(self.recomp_func.block_addrs)

        steps_taken = 0
        for smgr in smgrs:
            # only keep 1 state active at a time, queue the rest
            smgr.stashes['queue'] = []
            # holds states that returned from the target function
            smgr.stashes['returned'] = []
            # holds states that were pruned for reaching any defined limits
            # (ex: max steps)
            smgr.stashes['limit'] = []

        # maintains a pairing between states from the two functions
        # key: state in original function, value: state in recompiled function
        pairings = dict()

        while len(orig_smgr.active) > 0 and len(recomp_smgr.active) > 0:
            if isinstance(max_steps, int) and steps_taken > max_steps:
                log.warning("Reached max steps (%d), ending early" % max_steps)
                orig_smgr.move('active', 'limit')
                recomp_smgr.move('active', 'limit')
                status = "Completed"
                result = "Reached max steps so ending early:Functions passed differential analysis!"
                log.info("Reached max steps so ending early:Functions passed differential analysis!")
                return status, result, steps_taken, orig_smgr.stashes, recomp_smgr.stashes

            for smgr, curr_smgr in zip(smgrs, ['orig', 'recomp']):
                parent_state = smgr.stashes['active'].copy()
                # step active state

                smgr.step()
                child_states = smgr.stashes['active'].copy()

                # do not symbex called functions, simply return and continue
                self._fast_forward_states(smgr.active, curr_smgr)
                # filter states that have returned from the target function
                #log.debug(smgr.stashes)

                smgr.move('active', 'returned', (lambda s: s.addr == 0))
            log.debug("orig stash: " + str(orig_smgr.stashes))
            log.debug("recomp stash: " + str(recomp_smgr.stashes))
            # If one function returned earlier than the other, we have to
            # resync. Note that if they're equivalent, any path that gets the
            # other function to return should match.
            orig_num_returned = len(orig_smgr.stashes['returned'])
            recomp_num_returned = len(recomp_smgr.stashes['returned'])

            if (orig_num_returned > recomp_num_returned or
                    orig_num_returned < recomp_num_returned):
                log.warning("One function returned earlier than the other")
                log.warning("States: %s vs. %s" % (str(orig_smgr), str(recomp_smgr)))
                if orig_num_returned > recomp_num_returned:
                    fix = self._resolve_early_return(orig_smgr, recomp_smgr)
                elif recomp_num_returned > orig_num_returned:
                    fix = self._resolve_early_return(recomp_smgr, orig_smgr)

                if not fix:
                    self.check_IO_equivalency(orig_smgr, recomp_smgr)
                    log.error("Functions have diverged because of early return!")
                    log.error("States: %s vs. %s" % (str(orig_smgr), str(recomp_smgr)))
                    status = "Completed"
                    result = "Functions have diverged because of early return"
                    return status, result, steps_taken, orig_smgr.stashes, recomp_smgr.stashes

            for smgr in smgrs:
                # only 1 active state at a time
                if (len(smgr.stashes['active']) < 1 and
                        len(smgr.stashes['queue']) > 0):
                    smgr.stashes['active'].append(smgr.stashes['queue'].pop())
                elif len(smgr.stashes['active']) > 1:
                    smgr.stashes['queue'] += smgr.stashes['active'][1:]
                    smgr.stashes['active'] = [smgr.stashes['active'][0]]

            steps_taken += 1

            log.info("%s vs. %s" % (str(orig_smgr), str(recomp_smgr)))

            # update pairings
            #
            # Note, performing this update pairs each successor in the original
            # function with a successor in the recompiled function. Therefore,
            # if this update fails, we have found a state with no companion,
            # meaning the two functions are not equivalent (by our definition).
            if not self._update_pairings(orig_smgr, recomp_smgr, pairings):
                # we have a desync, can we fix it?
                if len(orig_smgr.stashes['active']) == 0 or len(recomp_smgr.stashes['active']) == 0:
                    self.check_IO_equivalency(orig_smgr, recomp_smgr)
                    log.error("No active states left in Smgr! (Active States (#): Orig: " + str(len(orig_smgr.stashes['active'])) + "  - Recompiled: " + str(len(recomp_smgr.stashes['active'])) + ")")
                    status = "Interrupted"
                    result = "No active states left in Smgr! (Active States (#): Orig: " + str(len(orig_smgr.stashes['active'])) + "  - Recompiled: " + str(len(recomp_smgr.stashes['active'])) + ")"
                    return status, result, steps_taken, orig_smgr.stashes, recomp_smgr.stashes
                res, rets = self._attempt_resync_states(
                        orig_smgr.stashes['active'][0],
                        recomp_smgr.stashes['active'][0])

                if res is None:
                    log.error("Found state that cannot be paired after %d steps, functions are not equivalent!" % steps_taken)
                    status = "Completed"
                    result = "Functions are not equivalent:Found state that cannot be paired after " + str(steps_taken) + " steps!"
                    self._analyze_divergence(orig_smgr, recomp_smgr, pairings)
                    self.metrics.diverged_step = steps_taken
                    return status, result, steps_taken, orig_smgr.stashes, recomp_smgr.stashes

                # we've managed to resync, replace the active states and proceed
                orig_smgr.stashes['active'] = [res[0]]
                recomp_smgr.stashes['active'] = [res[1]]
                for smgr, rets in [(orig_smgr, rets[0]), (recomp_smgr, rets[1])]:
                    for ret in rets:
                        smgr.stashes['returned'].append(ret)

        self.check_IO_equivalency(orig_smgr, recomp_smgr)
        status = "Completed"
        result = "Functions passed differential analysis!"
        log.info("Functions passed differential analysis!")
        return status, result, steps_taken, orig_smgr.stashes, recomp_smgr.stashes

    def check_IO_equivalency(self, orig_smgr, recomp_smgr):

        orig_vals = []
        recomp_vals = []
        try:
            for curr_smgr, curr_vals in [(orig_smgr, orig_vals), (recomp_smgr, recomp_vals)]:
                for s in curr_smgr.stashes['returned']:
                    min = s.solver.min(s.regs.eax)
                    max = s.solver.max(s.regs.eax)
                    curr_vals.append((hex(min), hex(max)))
        except Exception as e:
            log.info("IO equivalency test interrupted:" + str(e))
            self.metrics.IO_res = "IO equivalency test interrupted:" + str(e)
            return

        set_orig_vals = set(orig_vals)
        set_recomp_vals = set(recomp_vals)

        orig_diffs = set_orig_vals - set_recomp_vals
        recomp_diffs = set_recomp_vals - set_orig_vals
        if orig_diffs or recomp_diffs:
            log.info("Functions failed IO equivalency test")
            self.metrics.IO_res = "Functions failed IO equivalency test"
        else:
            log.info("Functions passed IO equivalency test")
            self.metrics.IO_res = "Functions passed IO equivalency test"

        log.debug("All unique return values from original: " + str(set_orig_vals))
        log.debug("All unique return values from recompiled: " + str(set_recomp_vals))
        log.debug("All different return values from original: " + str(orig_diffs))
        log.debug("All different return values from recompiled: " + str(recomp_diffs))

        self.metrics.orig_ret_nums = len(orig_vals)
        self.metrics.orig_ret_unique_nums = len(set_orig_vals)
        self.metrics.unique_orig_vals = list(set_orig_vals)
        self.metrics.orig_diffs = list(orig_diffs)
        self.metrics.recomp_ret_nums = len(recomp_vals)
        self.metrics.recomp_ret_unique_nums = len(set_recomp_vals)
        self.metrics.unique_recomp_vals = list(set_recomp_vals)
        self.metrics.recomp_diffs = list(recomp_diffs)

    def _resolve_early_return(self, early_smgr, active_smgr):
        """Attempt to resync simulation managers when one side returned sooner
        than the other.

        Keyword Arguments:
        early_smgr -- The simulation manager that returned early.
        active_smgr -- The simulation manager that still has active states.

        Returns:
        True if resync was achieved, otherwise False.
        """
        self.metrics.early_ret_total += 1
        active_smgr.explore(find=0, num_find=1)

        if not active_smgr.stashes['found']:
            if active_smgr.errored:
                log.debug("Explore returns errored state")
            else:
                log.debug("Explore could not found a return state")
            
            log.warning("Failed to resync early return! Could not found a return state")
            return False

        found = active_smgr.stashes['found'][0]

        del active_smgr.stashes['found']
        early = early_smgr.stashes['returned'][-1]

        log.info("Resynced early return")
        self.metrics.early_ret_successful += 1
        active_smgr.stashes['returned'].append(found)
        active_smgr.stashes['active'] = []
        return True

    def _analyze_divergence(self, osmgr, rsmgr, pairings):
        """Analyzes the sets of discovered states to determine why the two
        functions do not match.

        Keyword Arguments:
        osmgr -- The simulation manager for the original function.
        rsmgr -- The simulation manager for the recompiled function.
        pairings -- Mapping from original states to matched recompiled states.
        """
        # recompiled states that diverged from the original
        rstates = [state for state in rsmgr.active
                if not state in pairings.values()]
        ostates = [state for state in osmgr.active
                if not state in pairings.keys()]

        log.info("The divergence is between %d original and %d new states." % (
                len(ostates), len(rstates)))

        # get and sort the diverging variables:
        diffs = dict()

        for ostate in ostates:
            for rstate in rstates:
                diff = self.compare_states(ostate, rstate)[1]
                if diff is None:
                    log.warning("%s and %s are suppose to be different, but "
                            "they aren't" % (ostate, rstate))
                    continue

                if not diff.cvar in diffs:
                    diffs[diff.cvar] = [diff]
                else:
                    diffs[diff.cvar].append(diff)
        self.metrics.diverged_var = [v for v in diffs.keys()]
        self.metrics.o_div_state_addr = [hex(s.addr) for s in ostates]
        self.metrics.r_div_state_addr = [hex(s.addr) for s in rstates]

        if self.dec_type == "Ida":
            log.info("Diverging variables: %s" % str([c for c in diffs]))
            for o in ostates:
                log.info("Orig:" + str(o))
            for r in rstates:
                log.info("Recomp: " + str(r))
            log.info("Common ancestors (original):  %s" %
                    str(set([hex(s.history.bbl_addrs[-1]) for s in ostates])))
            log.info("Common ancestors (recompile): %s" %
                    str(set([hex(s.history.bbl_addrs[-1]) for s in rstates])))

            caches = [self.cache_ostate_value, self.cache_rstate_value]
            min_max_temp = []
            for cvar in diffs:
                log.info("Ranges for %s:" % cvar)
                for diff in diffs[cvar]:
                    for curr_cache, state, solver, val in zip(caches, diff.states,
                                diff.solvers, diff.vals):
                        if id(state) in curr_cache.keys():
                            temp_dict = curr_cache[id(state)]
                            val_min, val_max = temp_dict[cvar]
                        else:
                            raise Exception("Something wrong with the caching!")
                        log.info("    [%#x - %#x]" % (val_min, val_max))
                        min_max_temp.append((val_min,val_max))
            self.metrics.o_min = hex(min_max_temp[0][0])
            self.metrics.o_max = hex(min_max_temp[0][1])
            self.metrics.r_min = hex(min_max_temp[1][0])
            self.metrics.r_max = hex(min_max_temp[1][1])
            try:
                self._check_certain_values(diffs)
            except Exception as ex:
                log.error("Exception: " + str(ex))
        elif self.dec_type == "Ghidra":
            log.info("Diverging variables: %s" % str([c for c in diffs]))
            for o in ostates:
                log.info("Orig:" + str(o))
            for r in rstates:
                log.info("Recomp: " + str(r))
            log.info("Common ancestors (original):  %s" %
                    str(set([hex(s.history.bbl_addrs[-1]) for s in ostates])))
            log.info("Common ancestors (recompile): %s" %
                    str(set([hex(s.history.bbl_addrs[-1]) for s in rstates])))

            caches = [self.cache_ostate_value, self.cache_rstate_value]
            min_max_temp = []
            for cvar in diffs:
                log.info("Ranges for %s:" % cvar)
                for diff in diffs[cvar]:
                    for curr_cache, state, solver, val in zip(caches, diff.states,
                                diff.solvers, diff.vals):
                        if id(state) in curr_cache.keys():
                            temp_dict = curr_cache[id(state)]
                            val_min, val_max = temp_dict[cvar]
                        else:
                            raise Exception("Something wrong with the caching!")
                        log.info("    [%#x - %#x]" % (val_min, val_max))
                        min_max_temp.append((val_min,val_max))
            self.metrics.o_min = hex(min_max_temp[0][0])
            self.metrics.o_max = hex(min_max_temp[0][1])
            self.metrics.r_min = hex(min_max_temp[1][0])
            self.metrics.r_max = hex(min_max_temp[1][1])
            try:
                self._check_certain_values(diffs)
            except Exception as ex:
                log.error("Exception: " + str(ex))

        elif self.dec_type == "Angr":
            log.info("Diverging variables: %s" % str([c for c in diffs]))
            for o in ostates:
                log.info("Orig state:" + str(o))
            for r in rstates:
                log.info("Recomp state: " + str(r))
            log.info("Common ancestors (original):  %s" %
                    str(set([hex(s.history.bbl_addrs[-1]) for s in ostates])))
            log.info("Common ancestors (recompile): %s" %
                    str(set([hex(s.history.bbl_addrs[-1]) for s in rstates])))

            caches = [self.cache_ostate_value, self.cache_rstate_value]
            min_max_temp = []
            for cvar in diffs:
                log.info("Ranges for %s:" % cvar)
                for diff in diffs[cvar]:
                    for curr_cache, state, solver, val in zip(caches, diff.states,
                                diff.solvers, diff.vals):
                        if id(state) in curr_cache.keys():
                            temp_dict = curr_cache[id(state)]
                            val_min, val_max = temp_dict[cvar]
                        else:
                            raise Exception("Something wrong with the caching!")
                        log.info("    [%#x - %#x]" % (val_min, val_max))
                        min_max_temp.append((val_min,val_max))
            self.metrics.o_min = hex(min_max_temp[0][0])
            self.metrics.o_max = hex(min_max_temp[0][1])
            self.metrics.r_min = hex(min_max_temp[1][0])
            self.metrics.r_max = hex(min_max_temp[1][1])
            try:
                self._check_certain_values(diffs)
            except Exception as ex:
                log.error("Exception: " + str(ex))

    def _check_certain_values(self, diffs):
        """ This is just to check a set of values and helps to debug during manual analysis. 
            This does not affect matching process.
        """
        for cvar in diffs:
            for diff in diffs[cvar]:
                o_solver = diff.solvers[0]
                r_solver = diff.solvers[1]
                o_val = diff.vals[0]
                r_val = diff.vals[1]

                size = o_val.size()
                val_ls = self.generate_values(size)

                if val_ls is None:
                    log.error("No implementation for this size!")
                    continue

                orig_satisfied_vals = []
                res = []
                try:
                    res = o_solver.eval_exact(o_val,1)
                    if len(res) == 1:
                        orig_satisfied_vals.append(hex(res[0]))
                except angr.errors.SimValueError:
                    for vl in val_ls:
                        try:
                            res = o_solver.eval_to_ast(o_val, 1, extra_constraints=[o_val == vl])
                        except angr.SimUnsatError:
                            continue
                        if res:
                            orig_satisfied_vals.append(hex(vl))

                recomp_satisfied_vals = []
                res = []
                try:
                    res = r_solver.eval_exact(r_val,1)
                    if len(res) == 1:
                        recomp_satisfied_vals.append(hex(res[0]))
                except angr.errors.SimValueError:
                    for vl in val_ls:
                        try:
                            res = r_solver.eval_to_ast(r_val, 1, extra_constraints=[r_val == vl])
                        except angr.SimUnsatError:
                            continue
                        if res:
                            recomp_satisfied_vals.append(hex(vl))

                log.info("Satisfied values:")
                log.info("      " + str(orig_satisfied_vals))
                log.info("      " + str(recomp_satisfied_vals))
                self.metrics.o_other_vals = orig_satisfied_vals
                self.metrics.r_other_vals = recomp_satisfied_vals

    def generate_values(self, size):
        """For debug purposes only. Does not affect matching process"""
        if size == 8:
            return [0x00, 0x4f, 0x7f, 0xbf, 0xff]
        if size == 16:
            return [0x0000, 0x4fff, 0x7fff, 0xbfff, 0xffff]
        elif size == 32:
            return [0x00000000, 0x4fffffff, 0x7fffffff, 0xbfffffff, 0xffffffff]
        elif size == 64:
            return [0x0000000000000000, 0x4fffffffffffffff, 0x7fffffffffffffff, 0xbfffffffffffffff, 0xffffffffffffffff]
        elif size == 128:
            return [0x00000000000000000000000000000000, 0x4fffffffffffffffffffffffffffffff, 0x7fffffffffffffffffffffffffffffff, 0xbfffffffffffffffffffffffffffffff, 0xffffffffffffffffffffffffffffffff]
        else:
            return None

    def _attempt_resync_states(self, state_a, state_b, max_steps=3):
        """Attempt to resync two states by exploring future states.

        Keyword Arguments:
        state_a -- Orig state that is out of sync.
        state_b -- Recomp state that is out of sync.
        max_steps -- Maximum number of steps to travel looking for a solution.

        Returns:
        A tuple of resynced states, or None if no sync could be made.
        """
        log.info("Attempting to resync states...")

        a_queue = [state_a]
        a_cans  = []
        b_queue = [state_b]
        b_cans  = []
        a_rets = []
        b_rets = []


        self.metrics.rematch_total += 1
        for step in range(max_steps):
            log.info("Resync step %d of %d" % (step + 1, max_steps))

            for queue, cans, rets, curr_smgr in [(a_queue, a_cans, a_rets, 'orig'), (b_queue, b_cans, b_rets, 'recomp')]:
                # if the queue is empty, we're done
                if len(queue) < 1:
                    break

                # get the next state off the queue
                next = queue.pop(0)
                # record it as a candidate for matching
                cans.append(next)

                # if it has already returned from the target function, there's
                # no point in stepping it further
                if next.addr == 0:
                    continue

                # step to get successors
                try:
                    succs = next.step()
                except angr.errors.SimEngineError:
                    continue
                except angr.errors.SimMemoryAddressError:
                    continue

                # fast-forward through any states that shouldn't be analyzed
                self._fast_forward_states(succs, curr_smgr)

                # queue states that can still be stepped, throw the rest in the
                # candidate list
                queue += [s for s in succs if s.addr != 0]
                #cans += [s for s in succs if s.addr == 0]
                rets += [s for s in succs if s.addr == 0]


        # reached step limit, throw remaining queue in candidate lists
        a_cans += a_queue
        b_cans += b_queue

        # attempt resync via pair-wise comparison
        log.info("Comparing %d original states against %d recompiled states" % (
                len(a_cans), len(b_cans)))

        matches = list()
        for a_can in a_cans:
            for b_can in b_cans:
                if self.compare_states(a_can, b_can)[0]:
                    matches.append((a_can, b_can))

        if len(matches) > 1:
            log.warning("Multiple (%d) possible matches found" % len(matches))

        if len(matches) > 0:
            pick = matches[0]
            log.info("Resync %s to %s" % (pick[0], pick[1]))
            self.metrics.rematch_successful += 1
            return pick, (a_rets, b_rets)

        log.warning("Failed to resync states")
        return None, None

    def _fast_forward_states(self, states, curr_smgr):
        """Fast forward states over logic that should not be compared such as:

        1. Calls to external functions.
        """
        for state in states:
            if state.history.jumpkind == 'Ijk_Call':
                # return immediately, do not execute external functions
                if curr_smgr == 'orig':
                    self.metrics.o_total_func_calls += 1
                    jump_target_addr = state.solver.eval(state.history.jump_target)
                    self.metrics.o_unique_func_calls.add(jump_target_addr)
                elif curr_smgr == 'recomp':
                    self.metrics.r_total_func_calls += 1
                    jump_target_addr = state.solver.eval(state.history.jump_target)
                    self.metrics.r_unique_func_calls.add(jump_target_addr)
                else:
                    raise("No such smgr! There is something wrong")
                state.regs.ip = state.stack_pop()
                state.regs.rax = claripy.BVS("ret", state.arch.bits)

    def _update_pairings(self, orig_smgr, recomp_smgr, pairings):
        """Updates the mapping from states in the original function to states in
        the recompiled function.

        Returns:
        True on success, otherwise False.
        """
        # prune states we don't have to track anymore
        # (can't modify dict while iterating it)
        to_del = set()
        for orig in pairings:
            recomp = pairings[orig]
            if (not orig in orig_smgr.active and
                    not recomp in recomp_smgr.active):
                to_del.add(orig)
        for state in to_del:
            del pairings[state]

        # (again, can't modify while iterating)
        to_add = list()
        for state in orig_smgr.active:
            if state in pairings:
                # already paired
                continue

            # state isn't paired, find a companion
            pending_pairs = [t[1] for t in to_add]
            candidates = [state for state in recomp_smgr.active
                    if not state in pairings.values() and
                    not state in pending_pairs]

            # pick the candidate where the internal states match
            found = False
            for can in candidates:
                if self.compare_states(state, can)[0]:
                    to_add.append((state, can))
                    found = True
                    break

            if not found:
                # if this point is reached, we've failed to pair this state
                log.warning("Failed to find matching state for: %s" % str(state))
                log.info("Candidates: %s" % str(candidates))
                return False

        # commit new pairings
        for key, val in to_add:
            pairings[key] = val

        # by this point, all active states in the original function have been
        # paired; make sure the same holds true for the recompiled function
        leftovers = [state for state in recomp_smgr.active
                if not state in pairings.values()]
        if len(leftovers) > 0:
            log.warning("Failed to find matching states for: %s" % str(leftovers))
            return False

        # all states paired on both sides
        return True
