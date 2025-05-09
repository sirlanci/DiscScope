from datetime import datetime
import utils
import os
import shutil

import logging

import diff_analysis
from traceback import format_exc

import tempfile
from IPython import embed


log = logging.getLogger(__name__)

class GhidraDecompiler(object):
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
        self.gh_dir_tmp = self.tmp_dir.name
        self.gh_rep_dir = os.path.join(self.tmp_dir.name, "decomp_out_ghidra.rep")
        self.gh_dir = self.gh_dir_tmp
        
        #self.gh_dir = "/tmp/decomp_out_ghidra.rep"

    def decompile_ghidra(self, main_bin, func):
        '''decompile one function.
        Args:
            func (ghidra.program.model.listing.Function): function to be decompiled
        Returns:
            string: decompiled psuedo C code
        '''
        log.info("Decompiling function: %s" % func.name)
        
        GPath = os.path.join(os.getcwd(), "decompilers/ghidra_10.1.2_PUBLIC/support/analyzeHeadless")

        SrcPath = os.path.join(os.getcwd(), "src") 
        command = str(GPath) + " " + self.gh_dir_tmp + " decomp_out_ghidra" + " -import " + str(main_bin) + " -scriptPath " + str(SrcPath) + " -postscript ghidra_decompiler.py " + str(func.name) + " " + str(self.gh_dir)
        log.info(command)
        os.system(command)

        decomp_gh = ""
        if os.path.isfile(os.path.join(self.gh_dir, "temp_gh.c")):
            with open(os.path.join(self.gh_dir, "temp_gh.c"), "r") as f:
                decomp_gh = f.read()
        else:
            raise Exception("Ghidra Decompilation failed!")

        if decomp_gh == "":
            raise Exception("Ghidra Decompilation failed!")

        c_text_gh = ""
        c_text_gh += decomp_gh

        #Type fix in ghidra decompile out
        log.warning(c_text_gh)
        self.metrics.sloc = c_text_gh.count('\n')
        
        # write C source file
        c_src_gh = os.path.join(self.gh_dir, "decompiled_gh.c")
        with open(c_src_gh, 'w') as gh_ofile:
            gh_ofile.write(c_text_gh)
            log.info("Wrote decompiled C code to: %s" % c_src_gh)

        #iterate final var set to put them in metrics
        with open(os.path.join(self.gh_dir, "vardefs.l"), "r") as f2:
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

        return decomp_gh

    def main_analysis(self):

        c_src_gh = os.path.join(self.gh_dir, "decompiled_gh.c")

        if os.path.exists(self.gh_rep_dir):
            shutil.rmtree(self.gh_rep_dir)

        ##############################################################################################################################
        #################################################### GHIDRA Decompilation ####################################################
        try:
            log.info("\n\n########## GHIDRA Decompilation ##########")

            dec_time_start = datetime.now().timestamp()
            decomp_gh = self.decompile_ghidra(self.main_bin, self.func)
            dec_time_end = datetime.now().timestamp()
            self.metrics.dec_time = dec_time_end - dec_time_start

            #################################################### Recompile GHIDRA Output ####################################################
            recompiled_so_gh = os.path.join(self.gh_dir, 'decompiled_gh.o')
            c_stdout, c_stdout_gh_f = utils.mksfile(self.gh_dir, 'w', 'stdout-')
            c_stderr, c_stderr_gh_f = utils.mksfile(self.gh_dir, 'w', 'stderr-')
            try:
                log.info("\n\n########## GHIDRA Recompilation ##########")

                check_bool = self.cc.compile(
                        [os.path.basename(c_src_gh)],
                        os.path.basename(recompiled_so_gh),
                        stdout=c_stdout,
                        stderr=c_stderr,
                        shared=True,
                        cwd=os.path.dirname(c_src_gh)
                )
                if not check_bool:
                    #print(check_bool)
                    shutil.copyfile(c_stderr_gh_f, os.path.join(self.artifacts_root, "std/ghidra", os.path.basename(self.main_bin).replace(".bin", "") + "+" + str(self.func.name)))
                    raise Exception("Recompilation failed with unkown reason")

                log.info("Successfully recompiled: %s" % recompiled_so_gh)

                #################################################### GHIDRA Differential Analysis ####################################################
                # differential analysis to determine whether the decompile is accurate
                try:
                    log.info("\n\n########## GHIDRA Differential Analysis ##########")
                    diff_mgr = diff_analysis.SymbolicDifferentialAnalysis(
                            self.bin_name,
                            self.proj,
                            self.cfg,
                            None,
                            self.func,
                            recompiled_so_gh,
                            "Ghidra",
                            self.gh_dir,
                            self.start_time,
                            self.metrics
                    )
                    log.info("Starting differential analysis")
                    try:
                        symbex_start_time = datetime.now().timestamp()
                        status, result, steps_taken, o_stashes, r_stashes = diff_mgr.analyze(self.func, "GHIDRA", max_steps=self.max_steps)
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
                        os.path.basename(c_stdout_gh_f),
                        os.path.basename(c_stderr_gh_f),
                        self.gh_dir))
                log.info("You can manually fix the source files in %s and restart from"
                        " here by rerunning the same command with --restart")

                self.cc.write_makefile(os.path.join(self.gh_dir, 'Makefile'), self.cc.last_cmd)
                log.info("A Makefile has been written to %s for debugging" % self.gh_dir)
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

        #Remove ghidra decompilation files
        if os.path.exists(self.gh_rep_dir):
            shutil.rmtree(self.gh_rep_dir)
        if os.path.exists(self.gh_rep_dir.replace(".rep", ".gpr")):
            os.remove(self.gh_rep_dir.replace(".rep", ".gpr"))

        #Move artifacts to a permanent location
        artifacts_ghidra = os.path.join(self.artifacts_root, "ghidra")
        if os.path.exists(self.gh_dir):
            if os.path.exists(os.path.join(artifacts_ghidra, os.path.basename(self.main_bin).replace(".bin", ""))):
                shutil.move(self.gh_dir, os.path.join(artifacts_ghidra, os.path.basename(self.main_bin).replace(".bin", ""), str(self.func.name)))
            else:
                os.mkdir(os.path.join(artifacts_ghidra, os.path.basename(self.main_bin).replace(".bin", "")))
                shutil.move(self.gh_dir, os.path.join(artifacts_ghidra, os.path.basename(self.main_bin).replace(".bin", ""), str(self.func.name)))

        #################################################### END OF GHIDRA ####################################################
