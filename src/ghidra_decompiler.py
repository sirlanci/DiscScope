from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
import ghidra.app.decompiler.ClangVariableDecl as ClangVariableDecl
import sys
import logging
import os

log = logging.getLogger(__name__)
args = getScriptArgs();
funcname = args[0]
gh_dir = args[1]

program = getCurrentProgram()
ifc = DecompInterface()
ifc.openProgram(program)

# here we assume there is only one function named `main`
function = getGlobalFunctions(funcname)[0]

# decompile the function and print the pseudo C
results = ifc.decompileFunction(function, 0, ConsoleTaskMonitor())

c_code = results.getCCodeMarkup()
#Take variables declarations from decompilation
tokens = (c_code.Child(i) for i in range(c_code.numChildren()))

gh_var_ls = results.function.getAllVariables()
offset_dict = {}


for var in gh_var_ls:
	if var.stackVariable:
		offset_dict[str(var.name)] = str(var.stackOffset)

dec_vars = []
for token in tokens:
	if type(token) == ClangVariableDecl:
		var_name = str(token.getHighVariable().name)
		if "local" in var_name: 
			if hasattr(token.getDataType(), "POINTER_NAME"):
				stack_offset = offset_dict[var_name]
				var_size = token.getDataType().getDataType().getLength()
				is_ptr = "1"
				ptr_size = token.getDataType().getLength()
				dec_vars.append((var_name, stack_offset, var_size, is_ptr, ptr_size))
			else:
				stack_offset = offset_dict[var_name]
				var_size = token.getDataType().getLength()
				is_ptr = "0"
				ptr_size = "0"
				dec_vars.append((var_name, stack_offset, var_size, is_ptr, ptr_size))

with open(os.path.join(gh_dir, "vardefs.l"), "w") as f:
	for var_name, stack_offset, var_size, is_ptr, ptr_size in dec_vars:
		f.write(str(var_name) + ";" + str(stack_offset) + ";" + str(var_size) + ";" + str(is_ptr) + ";" + str(ptr_size) + "\n")

with open(os.path.join(gh_dir, "temp_gh.c"), "w") as f:
	f.write(results.getDecompiledFunction().getC())