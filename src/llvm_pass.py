import os
import sys
from IPython import embed
import logging

import networkx as nx
# import matplotlib.pyplot as plt
# from networkx.drawing.nx_pydot import graphviz_layout

log = logging.getLogger(__name__)

pointer_list = []
temp_stack = 0

def get_pdg_raw(filename):
    c_file = filename
    filename = os.path.splitext(filename)[0]
    ll_file = filename + ".ll"
    raw_file = filename + ".raw"
    ll_flags="-S -c -g -emit-llvm"
    no_flags="-Wno-int-conversion"
    cmd1 = "clang-15 " + ll_flags + " " + no_flags + " " + c_file + " -o " + ll_file
    os.system(cmd1)

    if os.path.isfile(ll_file):
        opt_args = "-disable-output --enable-new-pm=0"
        load_plugin = "-load=src/pdg-raw.so"
        plugin_args = "-pdg-raw" 
        cmd2 = "opt-15 " + opt_args + " " + load_plugin + " " + plugin_args + " < " + ll_file + " 2> " + raw_file
        os.system(cmd2)

    if os.path.isfile(raw_file):
        return True

    return False

def parse_debug_info(file_ll):
    lines = []
    use_var_ref = {}
    var_ref_name = {}
    use_var_name = {}
    if not os.path.exists(file_ll):
        raise Exception("LLVM IR file (ll) not found!")
    with open(file_ll, "r") as f:
        lines = f.readlines()

        for line in lines:
            if "llvm.dbg.declare" in line and "call" in line:
                use_ref = line.split("metadata ptr ")[1].split(", ")[0]
                var_ref = line.split("metadata ")[2].split(", ")[0]
                use_var_ref[use_ref] = var_ref
            elif "DILocalVariable" in line:
                var_ref = line.split(" = ")[0]
                var_name = line.split("name: ")[1].split(", ")[0].replace('"', '')
                var_ref_name[var_ref] = var_name
        
        for e, k in use_var_ref.items():
            use_var_name[e] = var_ref_name[k]

    return use_var_name

def build_graph(path, file_raw):
    lines = []

    if not os.path.exists(file_raw):
        raise Exception("LLVM dependency file (raw) not found!")

    with open(file_raw, "r") as f:
        lines = f.readlines()

    G = nx.DiGraph()

    for line in lines:
        try:
            left, right = line.split(" -> ")
        except:
            raise Exception("Exception in splitting of '->'")
        
        right = right.replace("\n", "")
        G.add_edge(str(left), str(right))

    # try:
    #     pos = graphviz_layout(G, prog="dot")
    #     plt.figure(3,figsize=(36,80))
    #     nx.draw_networkx(G, pos=pos, arrowsize=15, node_color="white", node_size=1000, font_size=5)
    # except:
    #     plt.figure(3,figsize=(36,80))
    #     nx.draw_networkx(G, arrowsize=15, node_color="white", node_size=1000, font_size=5)

    # fig = plt.gcf()
    # plt.draw()
    return G

def get_leaf_nodes(G):
    leaf_nodes = []
    for n in G.nodes():
        if G.out_degree(n)==0 and G.in_degree(n)>=1 and\
            (n[:7] == "  store" or n[:5] == "store" or\
            n[:7] == "  br i1" or n[:5] == "br i1" or\
            n[:11] == "  call void" or n[:5] == "call void" or "= call i32" in n or "= call i64" in n):            
            leaf_nodes.append(n)

    return leaf_nodes

def reach_root(G, n):
    global pointer_list, temp_stack

    for parent, curr in G.in_edges(n):
        if "inttoptr" in parent or "getelementptr" in parent:
            temp_stack = 1
            log.info("Pointer found - " + str(parent))
            #embed()
        if G.in_degree(parent) > 0:
            reach_root(G, parent)
        else:
            log.info("This is root - " + str(parent))
            if temp_stack == 1:
                temp_stack = 0
                var_ref = parent.split(" = ")[0].replace(" ", "")
                pointer_list.append(var_ref)

def climb_graph(G, leaf_nodes):
    for n in leaf_nodes:
        if G.in_degree(n) > 0:
            reach_root(G, n)

def dump_ptr_vars(use_var_name, file_ptr_out):
    global pointer_list
    pointer_vars = []
    with open(file_ptr_out, "w") as f:
        for p in set(pointer_list):
            if p in use_var_name.keys():
                v_name = use_var_name[p]
                pointer_vars.append(v_name)
                f.write(v_name + "\n")
    return pointer_vars

def gen_graph(filename):
    log.debug("Graph build and analysis...")
    filename = os.path.splitext(filename)[0]
    file_ll = filename + ".ll"
    file_raw = filename + ".raw"
    file_ptr_out = os.path.join(os.path.dirname(filename), "pointers.l")

    G = build_graph(os.path.dirname(filename), file_raw)
    use_var_name = parse_debug_info(file_ll)
    leaf_nodes = get_leaf_nodes(G)
    climb_graph(G, leaf_nodes)
    pointer_vars = dump_ptr_vars(use_var_name, file_ptr_out)

    return pointer_vars
