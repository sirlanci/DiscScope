import os
import angr
import sys
from optparse import OptionParser
import BinInfo
from IPython import embed

import logging
from colorlog import ColoredFormatter
from datetime import datetime 

PROGRAM_USAGE = "Usage: %prog [options]"

log = logging.getLogger(__name__)
log.propagate = False
analysis_start_time = 0

def parse_args():
    """Parse and validate command line arguments."""
    parser = OptionParser(usage=PROGRAM_USAGE)

    parser.add_option('-o', '--obin', action='store', type='str',
            default=None, help="Path to original binary")

    parser.add_option('-r', '--rbin', action='store', type='str',
            default=None, help="Path to recompiled binary")

    parser.add_option('-f', '--func', action='store', type='str',
            default=None, help="Name of the function to analyze")

    parser.add_option('-d', '--decompiler', action='store', type='str',
            default=None, help="Name of the decompiler used")

    parser.add_option('-l', '--logging', action='store', type='int',
            default=20, help='Log level [10-50] (default: 20 - Info)')
    
    parser.add_option('--max-steps', action='store', type='int', default=None,
            help="Max number of steps to explore funtions")

    parser.add_option('--num-ret', action='store', type='int', default=100,
            help="Continue exploration till finding number of return")
    
    opts, args = parser.parse_args()

    if opts.func is None:
        print("No target function specified (--func), nothing to do")
        sys.exit(1)

    if opts.obin is None:
        print("Original binary path is not specified (--obin)")
        sys.exit(1)

    if opts.rbin is None:
        print("Recompiled binary path is not specified (--rbin)")
        sys.exit(1)

    return opts

def set_logger(opts):
    logging.getLogger('angr.analyses').setLevel(41)
    logging.getLogger('cle').setLevel(logging.ERROR)

    stream = logging.StreamHandler()
    stream = logging.FileHandler("{0}/{1}.log".format("out/terminal_log", os.path.basename(opts.obin) + "+" + str(opts.func) + "+" + str(opts.decompiler)))
    stream.setLevel(logging.DEBUG)
    stream.setFormatter(ColoredFormatter(
        "%(log_color)s%(levelname)-8s%(reset)s | %(log_color)s%(asctime)-24s%(reset)s | %(log_color)s%(module)-13s%(reset)s | %(log_color)s%(message)s%(reset)s",
        log_colors={
            'DEBUG':    'green',
            'INFO':     'purple',
            'WARNING':  'yellow',
            'ERROR':    'red',
            'CRITICAL': 'red,bg_white',
        }))

    logging.getLogger(__name__).addHandler(stream)

    logging.getLogger(__name__).setLevel(opts.logging)
    logging.getLogger(__name__).propagate = False
    logging.getLogger(__name__).addHandler(stream)

    logging.getLogger(angr.__name__).setLevel(max(opts.logging, logging.WARNING))
    logging.getLogger(angr.__name__).propagate = False
    logging.getLogger(angr.__name__).addHandler(stream)
    
    logging.getLogger(BinInfo.__name__).setLevel(opts.logging)
    logging.getLogger(BinInfo.__name__).propagate = False
    logging.getLogger(BinInfo.__name__).addHandler(stream)
    
def get_ret_vals(bin_info):

    vals = []
    for s in bin_info.smgr.stashes['found']:
        min = s.solver.min(s.regs.eax)
        max = s.solver.max(s.regs.eax)
        vals.append((min, max))
        
    return vals

def dump_res(status, res, orig_info, recomp_info):
    global analysis_start_time
    analysis_end_time = datetime.now().timestamp()
    analysis_time = analysis_end_time - analysis_start_time

    with open("IO_analysis.log", "a") as f:
        f.write(orig_info.bin_name + ";" + str(analysis_time) + ";" + str(orig_info.func_name) + ";" + str(orig_info.dec_name) + ";" + str(status) + ";" + str(res) + "\n")

def compare_returns(orig_info, recomp_info, opts):
    log.info("Get return values for original")
    orig_ret_vals = get_ret_vals(orig_info)
    set_orig_ret_vals = set(orig_ret_vals)
    log.info("Number of total returns in original: " + str(len(orig_ret_vals)))
    log.info("All return values in original: " + str(orig_ret_vals))
    log.info("Number of unique returns in original: " + str(len(set_orig_ret_vals)))
    log.info("Unique return values in original: " + str(set_orig_ret_vals))

    log.info("Get return values for recompiled")
    recomp_ret_vals = get_ret_vals(recomp_info)
    set_recomp_ret_vals = set(recomp_ret_vals)
    log.info("Number of total returns in recomp: " + str(len(recomp_ret_vals)))
    log.info("All return values in recomp: " + str(recomp_ret_vals))
    log.info("Number of unique returns in recomp: " + str(len(set_recomp_ret_vals)))
    log.info("Unique recomp return values: " + str(set_recomp_ret_vals))

    log.info("Compare return values")
    orig_diffs = set_orig_ret_vals - set_recomp_ret_vals
    recomp_diffs = set_recomp_ret_vals - set_orig_ret_vals
    log.info("The differences of orig: " + str(orig_diffs))
    log.info("The differences of recomp: " + str(recomp_diffs))
    if orig_diffs or recomp_diffs:
        res = "Functions failed IO equivalency test"
        status = "Completed"
        log.info(res)
        dump_res(status, res, orig_info, recomp_info)
    else:
        res = "Functions passed IO equivalency test"
        status = "Completed"
        log.info(res)
        dump_res(status, res, orig_info, recomp_info)

def main():
    global analysis_start_time
    opts = parse_args()
    set_logger(opts)
    try:
        orig_info = BinInfo.BinInformation(opts.obin, opts.func, opts.decompiler)
    except Exception as e:
        dump_res("Exception", "Original initialization threw an exception:" + str(e), orig_info, recomp_info)
    try:
        recomp_info = BinInfo.BinInformation(opts.rbin, opts.func, opts.decompiler)
    except Exception as e:
        dump_res("Exception", "Recompiled initialization threw an exception:" + str(e), orig_info, recomp_info)

    analysis_start_time = datetime.now().timestamp()

    log.info("Exploring original binary...")
    try:
        orig_info.smgr.explore(n=opts.max_steps, find=0, num_find=opts.num_ret)
    except Exception as e:
        dump_res("Exception", "Original explore threw an exception:" + str(e), orig_info, recomp_info)
        
    log.info("Exploring recompiled binary...")
    try:
        recomp_info.smgr.explore(n=opts.max_steps, find=0, num_find=opts.num_ret)
    except Exception as e:
        dump_res("Exception", "Recompiled explore threw an exception:" + str(e), orig_info, recomp_info)

    try:
        compare_returns(orig_info, recomp_info, opts)
    except Exception as e:
        dump_res("Exception", "Comparison threw an exception:" + str(e), orig_info, recomp_info)

if __name__ == "__main__":
    main()
    sys.exit()
