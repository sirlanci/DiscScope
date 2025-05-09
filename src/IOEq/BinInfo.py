import angr
import os

class BinInformation(object):

    def __init__(self, path, funcname, decompiler_name):
        self.bin_name = os.path.basename(path)
        self.func_name = funcname
        self.dec_name = decompiler_name
        self.proj = angr.Project(
                path,
                auto_load_libs=False,
                load_debug_info=True,
                ld_path=(),
                main_opts={"base_addr": 0x400000}
        )


        self.cfg = self.proj.analyses.CFGFast(
                binary=self.proj.loader.main_object,
                objects=[self.proj.loader.main_object],
                cross_references=True,
                normalize=True,
                show_progressbar=True
        )
        self.proj.analyses.CompleteCallingConventions(recover_variables=True)
        self.cfg.project.analyses.CompleteCallingConventions(recover_variables=True)

        self.func = self.cfg.functions.function(name=funcname)

        self.sim_opts = {angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
                         angr.sim_options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS}

        self.init_state = self.proj.factory.call_state(
                self.func.addr,
                ret_addr=0,
                add_options=self.sim_opts
        )

        self.smgr = angr.SimulationManager(
                self.proj,
                active_states=[self.init_state.copy()]
        )
