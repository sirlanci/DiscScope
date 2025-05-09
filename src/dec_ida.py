from datetime import datetime
import utils
import os
import shutil

import logging

import diff_analysis
from traceback import format_exc

import tempfile
from IPython import embed

import llvm_pass

log = logging.getLogger(__name__)

class IdaDecompiler(object):
    def __init__(self, artifacts_root, main_bin, proj, cfg, func, cc, max_steps, dec_type, start_time, metrics):
        self.artifacts_root = artifacts_root
        self.main_bin = main_bin
        self.bin_name = os.path.basename(main_bin)
        self.proj = proj
        self.cfg = cfg
        self.func = func
        self.cc = cc
        self.max_steps = max_steps
        self.dec_type = dec_type
        self.start_time = start_time
        self.metrics = metrics

        self.tmp_dir = tempfile.TemporaryDirectory()
        self.ida_dir = self.tmp_dir.name

        #self.ida_dir = "/tmp/decomp_out_ida"

    def decompile_ida(self, func, c_src_ida):

        ida_path = os.path.join(os.getcwd(), "decompilers/ida-7.6/idat64")
        
        #Get decompilation out of IDA
        hexrays = "-Ohexrays:-errs:" + str(os.path.join(self.ida_dir, "decompiled.c")) + ":" + str(func.name)
        command = str(ida_path) + " " + str(hexrays) + " -c -A " + self.main_bin
        log.info(command)
        os.system(command)
        
        #Get variable definitions from IDA
        script_path = os.path.join(os.getcwd(), "src/ida_alias_decompiler.py")
        command = str(ida_path) +  " -S'" + str(script_path) + " " + str(func.name) + " " + str(self.ida_dir) + "'" + " -A -c " + str(self.main_bin)
        embed()
        log.info(command)
        os.system(command)

        hexray_out = []
        if os.path.isfile(os.path.join(self.ida_dir, "decompiled.c")):
            with open(os.path.join(self.ida_dir, "decompiled.c"), "r") as f_hexray:
                lines = f_hexray.readlines()
                for line in lines:
                    hexray_out.append(line)
                    if "//----- (00000000" in line:
                        break
        else:
            raise Exception("IDA Decompilation failed! decompiled.c not found")

        if os.path.isfile(os.path.join(self.ida_dir, "decompiled_via_script.c")):
            with open(os.path.join(self.ida_dir, "decompiled_via_script.c"), "r") as f_script:
                lines = f_script.readlines()
                self.metrics.sloc = len(lines)  
                for line in lines:
                    hexray_out.append(line)
        else:
            raise Exception("IDA Decompilation failed! decompiled_via_script.c not found")

        with open(os.path.join(self.ida_dir, "decompiled_modified.c"), "w") as f_modified:
            f_modified.writelines(hexray_out)


        decomp_ida = ""
        with open(os.path.join(self.ida_dir, "decompiled_modified.c"), "r") as f1:
            decomp_ida = f1.read()

        c_text_ida = decomp_ida.replace("__fastcall", " ").replace("*__fastcall", " ")
        
        # write C source file
        with open(c_src_ida, 'w') as f:
            f.write(c_text_ida)
            log.info("Wrote decompiled C code to: %s" % c_src_ida)

        res = llvm_pass.get_pdg_raw(c_src_ida)
        vars_to_ignore = []
        if res:
            vars_to_ignore = llvm_pass.gen_graph(c_src_ida)

        
        var_defs_final = []
        var_defs_all = []
        if os.path.join(self.ida_dir, "vardefs.l"):
            f3 = open(os.path.join(self.ida_dir, "non-ptr_vars.l"), "w")
            with open(os.path.join(self.ida_dir, "vardefs.l"), "r") as f2:
                lines = f2.readlines()
                for line in lines:
                    line = line.replace("\n", "")
                    name, offset, size, is_ptr, ptr_size = line.split(";")
                    var_defs_all.append((name, int(offset), int(size), int(is_ptr), int(ptr_size)))
                    if name in vars_to_ignore:
                        continue
                    var_defs_final.append((name, int(offset), int(size), int(is_ptr), int(ptr_size)))
                    f3.write(str(name) + ";" + str(offset) + ";" + str(size) + ";" + str(is_ptr) + ";" + str(ptr_size) + "\n")
            f3.close()
        else:
            raise Exception("IDA Decompilation failed! vardefs.l not found!")

        log.info(var_defs_all)
        log.info(vars_to_ignore)
        log.info(var_defs_final)

        #iterate final var set to put them in metrics
        with open(os.path.join(self.ida_dir, "non-ptr_vars.l"), "r") as f2:
            lines = f2.readlines()
            for line in lines:
                line = line.replace("\n", "")
                name, offset, size, is_ptr, ptr_size = line.split(";")
                if int(is_ptr):
                    self.metrics.total_vars += 1
                    self.metrics.pointer_vars += 1
                else:
                    self.metrics.total_vars += 1
                    self.metrics.non_pointer_vars += 1

        exts = ['.id0', '.id1', '.id2', '.nam', '.til']

        for ext in exts:
            tmpfile = self.main_bin + ext
            if os.path.exists(tmpfile):
                os.unlink(tmpfile)


        return c_text_ida, var_defs_all

    def main_analysis(self):
        c_src_ida = os.path.join(self.ida_dir, "decompiled_ida.c")
        

        '''if os.path.exists(self.ida_dir):
            shutil.rmtree(self.ida_dir)

        os.mkdir(self.ida_dir)'''
        ###########################################################################################################################
        #################################################### IDA DECOMPILATION ####################################################
        try:
            log.info("\n\n########## IDA Decompilation ##########")
            dec_time_start = datetime.now().timestamp()
            c_text_ida, var_defs = self.decompile_ida(self.func, c_src_ida)
            dec_time_end = datetime.now().timestamp()
            self.metrics.dec_time = dec_time_end - dec_time_start 

            log.warning(c_text_ida)
            #################################################### Recompile IDA Output ####################################################
            recompiled_so_ida = os.path.join(self.ida_dir, 'decompiled_ida.o')
            c_stdout, c_stdout_ida_f = utils.mksfile(self.ida_dir, 'w', 'stdout-')
            c_stderr, c_stderr_ida_f = utils.mksfile(self.ida_dir, 'w', 'stderr-')
            try:
                log.info("\n\n########## IDA Recompilation ##########")
                check_bool = self.cc.compile(
                        [os.path.basename(c_src_ida)],
                        os.path.basename(recompiled_so_ida),
                        stdout=c_stdout,
                        stderr=c_stderr,
                        shared=True,
                        cwd=os.path.dirname(c_src_ida)
                )
                if not check_bool:
                    #print(check_bool)
                    shutil.copyfile(c_stderr_ida_f, os.path.join(self.artifacts_root, "std/ida", os.path.basename(self.main_bin).replace(".bin", "") + "+" + str(self.func.name)))
                    raise Exception("Recompilation failed with unkown reason")

                log.info("Successfully recompiled: %s" % recompiled_so_ida)
                #################################################### IDA Differential Analysis ####################################################
                # differential analysis to determine whether the decompile is accurate
                try:
                    log.info("\n\n########## IDA Differential Analysis ##########")
                    ida_diff_mgr = diff_analysis.SymbolicDifferentialAnalysis(
                            self.bin_name,
                            self.proj,
                            self.cfg,
                            None,
                            self.func,
                            recompiled_so_ida,
                            "Ida",
                            self.ida_dir,
                            self.start_time,
                            self.metrics
                    )

                    log.info("Starting differential analysis")
                    try:
                        symbex_start_time = datetime.now().timestamp()
                        status, result, steps_taken, o_stashes, r_stashes = ida_diff_mgr.analyze(self.func,
                                                    "IDA", max_steps=self.max_steps)
                        symbex_end_time = datetime.now().timestamp()
                        self.metrics.get_stashes(o_stashes, r_stashes)
                        self.metrics.symbex_time = symbex_end_time - symbex_start_time
                        self.metrics.status = status
                        self.metrics.result = result
                        self.metrics.total_stepping = steps_taken
                    except KeyboardInterrupt:
                        log.warning("Keyboard interrupt")
                        #return EXIT_FAILURE
                    except Exception as ex:
                        self.metrics.status = 'Exception'
                        self.metrics.result = 'Diff-Analyze failed:' + str(ex)
                        log.error("Uncaught exception during differential analysis: %s" % str(ex))
                        log.debug("Traceback: %s" % format_exc())
                        #return EXIT_FAILURE

                except KeyboardInterrupt:
                    log.warning("Keyboard interrupt")
                    #return EXIT_FAILURE
                except Exception as ex:
                    self.metrics.status = 'Exception'
                    self.metrics.result = 'Diff-Initialize failed:' + str(ex)
                    log.error("Failed to setup differential analysis: %s" % str(ex))
                    log.debug("Traceback: %s" % format_exc())
                    #return EXIT_FAILURE

            except KeyboardInterrupt:
                log.warning("Keyboard interrupt")
                c_stdout.close()
                c_stderr.close()
                #return EXIT_FAILURE
            except Exception as ex:
                self.metrics.status = 'Exception'
                self.metrics.result = 'Recompilation failed:' + str(ex)
                log.error("Failed to compile decompiled code: %s" % str(ex))
                log.debug("Traceback: %s" % format_exc())
                log.error("See %s and %s in %s for details" % (
                        os.path.basename(c_stdout_ida_f),
                        os.path.basename(c_stderr_ida_f),
                        self.ida_dir))
                log.info("You can manually fix the source files in %s and restart from"
                        " here by rerunning the same command with --restart")

                self.cc.write_makefile(os.path.join(self.ida_dir, 'Makefile'), self.cc.last_cmd)
                log.info("A Makefile has been written to %s for debugging" % self.ida_dir)

                c_stdout.close()
                c_stderr.close()

                #return EXIT_FAILURE

        except KeyboardInterrupt:
            log.warning("Keyboard interrupt")
            #return EXIT_FAILURE
        except Exception as ex:
            self.metrics.status = 'Exception'
            self.metrics.result = 'Decompilation failed:' + str(ex)
            log.error("Failed to decompile: %s" % str(ex))
            log.error("Traceback: %s" % format_exc())
            #return EXIT_FAILURE
        #Move artifacts to a permanent location
        artifacts_ida = os.path.join(self.artifacts_root, "ida")
        if os.path.exists(self.ida_dir):
            if os.path.exists(os.path.join(artifacts_ida, os.path.basename(self.main_bin).replace(".bin", ""))):
                shutil.move(self.ida_dir, os.path.join(artifacts_ida, os.path.basename(self.main_bin).replace(".bin", ""), str(self.func.name)))
            else:
                os.mkdir(os.path.join(artifacts_ida, os.path.basename(self.main_bin).replace(".bin", "")))
                shutil.move(self.ida_dir, os.path.join(artifacts_ida, os.path.basename(self.main_bin).replace(".bin", ""), str(self.func.name)))

