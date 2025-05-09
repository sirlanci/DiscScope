import json
import logging
from optparse import OptionParser
import os
import sys
from traceback import format_exc

import angr

import compiler
import diff_analysis
import dwarf
import utils
import psutil

import shutil
from IPython import embed

import dec_angr
import dec_ghidra
import dec_ida
import metrics_db

import llvm_pass

from datetime import datetime 

os.environ["C_INCLUDE_PATH"] = os.path.join(os.getcwd(), "src/hexrays_include")

PROGRAM_USAGE = "Usage: %prog [options] binary output_directory"

EXIT_SUCCESS = 0
EXIT_FAILURE = 1

def parse_args():
    """Parse and validate command line arguments."""
    parser = OptionParser(usage=PROGRAM_USAGE)

    parser.add_option('-o', '--object', action='store', type='str',
            default=None, help="Object to be analyzed (default: main object)")
    parser.add_option('-n', '--name', action='store', type='str',
            default=None, help="Name of the function to decompile")
    parser.add_option('-r', '--rva', action='store', type='int',
            default=None, help="Relative virtual address of the function to"
            " decompile")
    parser.add_option('-p', '--prototype', action='store', type='str',
            default=None, help="Load function prototypes from provided file")
    parser.add_option('--load-libs', action='store_true', default=False,
            help="Load shared libraries imported by binary")
    parser.add_option('--load-dir', action='store', type='str', default=None,
            help="Load libraries from alternative directory")
    parser.add_option('--cc', action='store', type='str', default=None,
            help="Use CC as compiler")
    parser.add_option('--max-steps', action='store', type='int', default=None,
            help="Verify decompilation over up to MAX_STEPS steps")
    parser.add_option('--restart', action='store_true', default=False,
            help="Restart a previous session that ended in a failed compile")
    parser.add_option('-l', '--logging', action='store', type='int',
            default=20, help='Log level [10-50] (default: 20 - Info)')
    parser.add_option('--decompiler', action="store", type="str", default=None,
            help="Specify which decompiler will be used")

    opts, args = parser.parse_args()

    # input validation

    opts.decompiler = opts.decompiler.lower()

    if len(args) != 1:
        print("Wrong number of arguments", file=sys.stderr)
        parser.print_help()
        sys.exit(EXIT_FAILURE)

    if not os.path.isfile(os.path.realpath(args[0])):
        print("Does not exist or is not file: %s" % args[0], file=sys.stderr)
        sys.exit(EXIT_FAILURE)

    if opts.name is None and opts.rva is None:
        print("No target function specified (--name, --rva), nothing to do")
        sys.exit(EXIT_SUCCESS)

    if (isinstance(opts.load_dir, str) and
            not os.path.isdir(os.path.realpath(opts.load_dir))):
        print("Does not exist or is not directory: %s" % opts.load_dir,
                file=sys.stderr)
        sys.exit(EXIT_FAILURE)

    if (isinstance(opts.prototype, str) and
            not os.path.isfile(os.path.realpath(opts.prototype))):
        print("File not found: %s" % opts.prototype, file=sys.stderr)
        sys.exit(EXIT_FAILURE)

    return (opts, args[0])



def get_obj_by_name(loader, name):
    """Returns the object that best matches the provided name, or None if no
    candidate could be found."""
    match_base = set()

    for obj in loader.all_objects:
        if os.path.realpath(obj.binary) == os.path.realpath(name):
            # full match, no need to look further
            return obj

        if obj.binary_basename == name:
            match_base.add(obj)

    if len(match_base) < 1:
        log.error("Failed to find object with name: %s" % name)
        return None
    elif len(match_base) > 1:
        log.error("Multiple objects match name, %s" % name)
        return None

    # only 1 possible candidate
    return list(match_base)[0]

def configure_logs(opts):
    logging.getLogger(__name__).setLevel(opts.logging)
    logging.getLogger(__name__).propagate = False
    logging.getLogger(__name__).addHandler(stream)

    logging.getLogger(angr.__name__).setLevel(max(opts.logging, logging.WARNING))
    logging.getLogger(angr.__name__).propagate = False
    logging.getLogger(angr.__name__).addHandler(stream)
    
    logging.getLogger(compiler.__name__).setLevel(opts.logging)
    logging.getLogger(compiler.__name__).propagate = False
    logging.getLogger(compiler.__name__).addHandler(stream)
    
    logging.getLogger(diff_analysis.__name__).setLevel(opts.logging)
    logging.getLogger(diff_analysis.__name__).propagate = False
    logging.getLogger(diff_analysis.__name__).addHandler(stream)
    
    logging.getLogger(dwarf.__name__).setLevel(opts.logging)
    logging.getLogger(dwarf.__name__).propagate = False
    logging.getLogger(dwarf.__name__).addHandler(stream)
    
    logging.getLogger(utils.__name__).setLevel(opts.logging)
    logging.getLogger(utils.__name__).propagate = False
    logging.getLogger(utils.__name__).addHandler(stream)

    logging.getLogger(dec_angr.__name__).setLevel(opts.logging)
    logging.getLogger(dec_angr.__name__).propagate = False
    logging.getLogger(dec_angr.__name__).addHandler(stream)

    logging.getLogger(dec_ghidra.__name__).setLevel(opts.logging)
    logging.getLogger(dec_ghidra.__name__).propagate = False
    logging.getLogger(dec_ghidra.__name__).addHandler(stream)

    logging.getLogger(dec_ida.__name__).setLevel(opts.logging)
    logging.getLogger(dec_ida.__name__).propagate = False
    logging.getLogger(dec_ida.__name__).addHandler(stream)

    logging.getLogger(llvm_pass.__name__).setLevel(opts.logging)
    logging.getLogger(llvm_pass.__name__).propagate = False
    logging.getLogger(llvm_pass.__name__).addHandler(stream)

logging.getLogger('angr.analyses').setLevel(41)
logging.getLogger('cle').setLevel(logging.ERROR)

log = logging.getLogger(__name__)
log.propagate = False

from colorlog import ColoredFormatter
stream = logging.StreamHandler()
A_opts, A_main_bin = parse_args()
stream = logging.FileHandler("{0}/{1}.log".format("out/terminal_log", os.path.basename(A_main_bin) + "+" + str(A_opts.name) + "+" + str(A_opts.decompiler) + "+" + str("terminal")))
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

def main():

    opts, main_bin = parse_args()
    # CLE expects a tuple of load directories, massage CLI option
    if opts.load_dir is None:
        # uses default paths
        opts.load_dir = ()
    else:
        # uses only provided path
        opts.load_dir = (opts.load_dir)
    # configure logging
    configure_logs(opts)

    artifacts_root = os.path.join(os.getcwd(), "out")

    metrics = metrics_db.MetricAndResultLogger(os.path.basename(main_bin), opts.name, opts.decompiler)

    log.info("Start of Analysis!")
    start_time = datetime.now().timestamp()
    angr_prep_start_time = datetime.now().timestamp()
    # initialize a compiler
    try:
        cc = compiler.CCompiler(cc=opts.cc)
    except compiler.CompilerNotFound:
        log.error("Failed to find a suitable compiler, please check"
                " environment or specify one using --cc")
        return EXIT_FAILURE
    log.info("Using compiler: %s" % cc.compiler_bin)

    log.info("Loading: %s" % main_bin)
    try:
        proj = angr.Project(
                main_bin,
                auto_load_libs=opts.load_libs,
                ld_path=opts.load_dir,
                main_opts={"base_addr": 0x400000}
        )
    except KeyboardInterrupt:
        log.warning("Keyboard interrupt")
        #return EXIT_FAILURE
    except Exception as ex:
        log.error("Failed to load binary: %s" % str(ex))
        log.error("Traceback: %s" % format_exc())
        #return EXIT_FAILURE

    # identify target object to decompile
    if opts.object is None:
        opts.object = proj.loader.main_object
    else:
        match = get_obj_by_name(proj.loader, opts.object)
        if match is None:
            log.error("Failed to find object: %s" % opts.object)
            #return EXIT_FAILURE
        else:
            opts.object = match

    log.info("Analyzing control flow of: %s" % opts.object.binary_basename)
    try:
        cfg = proj.analyses.CFGFast(
                binary=opts.object,
                objects=[opts.object],
                cross_references=True,
                normalize=True,
                show_progressbar=True
        )
        proj.analyses.CompleteCallingConventions(recover_variables=True)
        cfg.project.analyses.CompleteCallingConventions(recover_variables=True)

    except KeyboardInterrupt:
        log.warning("Keyboard interrupt")
        #return EXIT_FAILURE
    except Exception as ex:
        log.error("Failed to recover control flow: %s" % str(ex))
        log.debug("Traceback: %s" % format_exc())
        #return EXIT_FAILURE

    # identify target function to decompile
    if isinstance(opts.name, str):
        func = cfg.functions.function(name=opts.name)
        if func is None:
            log.error("Failed to find function by name: %s" % opts.name)
            #return EXIT_FAILURE
    elif isinstance(opts.rva, int):
        func = cfg.functions.function(addr=opts.object.mapped_base + opts.rva)
        if func is None:
            log.error("Failed to find function by address: %s+%#x" % (
                    opts.object.binary_basename, opts.rva))
            #return EXIT_FAILURE

    angr_prep_end_time = datetime.now().timestamp()
    metrics.angr_prep_time = angr_prep_end_time - angr_prep_start_time 

    #Start main analysis with corresponding decompiler
    if opts.decompiler == "angr":
        angrDec = dec_angr.AngrDecompiler(artifacts_root, main_bin, proj, cfg, func, cc,
                                opts.max_steps, opts.decompiler, start_time, metrics)
        angrDec.main_analysis()
    elif opts.decompiler == "ghidra":
        ghidraDec = dec_ghidra.GhidraDecompiler(artifacts_root, main_bin, proj, cfg, func, cc,
                                opts.max_steps, opts.decompiler, start_time, metrics)
        ghidraDec.main_analysis()
    elif opts.decompiler == "ida":
        idaDec = dec_ida.IdaDecompiler(artifacts_root, main_bin, proj, cfg, func, cc, 
                                opts.max_steps, opts.decompiler, start_time, metrics)
        idaDec.main_analysis()
    else:
        log.error("No decompiler with given name!")
    log.info("End of Analysis!\n\n")
    
    metrics.mem_usage = psutil.virtual_memory()[3]/(1024**2)
    metrics.fill_metric_dicts()
    metrics.dump_json()

    return EXIT_SUCCESS

if __name__ == '__main__':
    sys.exit(main())
