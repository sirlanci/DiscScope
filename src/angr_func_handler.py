from angr.analyses.reaching_definitions.function_handler import FunctionHandler
from IPython import embed
import claripy

class MyHandler(FunctionHandler):
    def __init__(self):
        self._analysis = None

    def hook(self, rda):
        self._analysis = rda
        return self

    def handle_local_function(self, state, function_address, call_stack, maximum_local_call_depth, visited_blocks,
                              dependency_graph, src_ins_addr=None, codeloc=None):

        temp = claripy.BVS("callret", 32)
        state.regs.eax = 0
        return True, state, visited_blocks, dependency_graph