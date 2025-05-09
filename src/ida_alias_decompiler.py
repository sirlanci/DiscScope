import ida_hexrays
import idaapi
import sys
import idc

def merge_vars(lvars_dict, ea):
	vuid = ida_hexrays.open_pseudocode(ea, 0)
	for key, value in lvars_dict.items():
		print(value)
		if len(value) > 1:
			var1 = value[0]
			for i in range(1,len(value)):
				vuid.map_lvar(value[i], var1)

idc.auto_wait()

args = idc.ARGV
funcname = args[1]
decomp_out_ida = args[2]

ea = get_name_ea_simple(funcname)
print(hex(ea))

decomp_out = ida_hexrays.decompile(ea)
func = ida_funcs.get_func(ea)

lvars_dict = dict()
lvars = []
lvars_set = set()
is_alias = False

with open(os.path.join(decomp_out_ida, "vardefs.l"), "w") as f1:
	for var in decomp_out.lvars:
		if var.name == "":
			continue
		elif not var.is_stk_var() or var.is_arg_var:
			continue

		var_offset = var.get_stkoff() - decomp_out.get_stkoff_delta() - func.frsize


		lvars.append(var_offset)
		if var_offset in lvars_dict.keys():

			temp_ls = lvars_dict[var_offset]
			temp_ls.append((var))
		else:
			lvars_dict[var_offset] = [(var)]


merge_vars(lvars_dict, ea)

modified_decomp_out = ida_hexrays.decompile(ea)

with open(os.path.join(decomp_out_ida, "decompiled_via_script.c"), "w") as f2:
    f2.write(str(modified_decomp_out) + "\n")

with open(os.path.join(decomp_out_ida, "vardefs.l"), "w") as f1:
	for var in modified_decomp_out.lvars:
		if var.name == "":
			continue
		elif not var.is_stk_var() or var.is_arg_var:
			continue

		var_offset = var.get_stkoff() - decomp_out.get_stkoff_delta() - func.frsize
		is_ptr = var.type().is_ptr()
		if is_ptr:
			is_ptr = 1
		else:
			is_ptr = 0

		if is_ptr:
			var_size = var.type().get_pointed_object().get_size()
			ptr_size = var.width
		else:
			var_size = var.width
			ptr_size = 0
		
		f1.write(str(var.name) + ";" + str(var_offset) + ";" + str(var_size) + ";" + str(is_ptr) + ";" + str(ptr_size) + "\n")


idc.exit()
	