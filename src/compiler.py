import logging
import os
import subprocess

import utils
from IPython import embed

log = logging.getLogger(name=__name__)

class CompilerNotFound(Exception):
    pass

class CCompiler(object):
    """A class that abstracts a system's C compiler."""

    _default_flags = ['-O0', '-g', '-Wall', '-I.']

    def __init__(self, cc=None):
        self.compiler_bin = self._pick_compiler(cc)
        self.last_cmd = list()

        if self.compiler_bin is None:
            raise CompilerNotFound("Compiler not found")

    def compile(self, c_files, output, stdout=None, stderr=None, flags=None,
                shared=False, cwd=None):
        """Compiles a C program.

        Keyword Arguments:
        c_files -- A list of C filepaths to compile.
        output -- Where resulting program should be outputtted to. If output
        already exists, it will be overwritten.
        stdout -- If provided, a filepath or IO object to write the compiler's
        stdout to.
        stderr -- If provided, a filepath or IO object to write the compiler's
        stderr to.
        flags -- If provided, a list of arguments to pass to the underlying
        compiler. If not provided, a default set of flags will be used.
        shared -- Whether the program should be compiled as a shared object, as
        opposed to a main executable.
        cwd -- If provided, a working directory for the underlying compiler,
        otherwise the current working directory will be used.

        Returns:
        True if compile was successful, otherwise False
        """
        if isinstance(c_files, str):
            # we want a list, even if there's only 1 C source file
            c_files = [c_files]

        if isinstance(stdout, str):
            stdout = open(stdout, 'w')
        if isinstance(stderr, str):
            stderr = open(stderr, 'w')

        # prepare compiler arguments
        comp_args = list()

        if flags is None:
            comp_args += self._default_flags
        else:
            comp_args += flags

        if shared:
            comp_args = ['-c'] + comp_args
            #comp_args = ['-fpic'] + comp_args

        comp_args += ['-o', output] + c_files

        # we're ready to compile!
        cmd = [self.compiler_bin] + comp_args
        log.debug("Executing: %s" % str(cmd))
        self.last_cmd = cmd

        try:
            res = subprocess.run(
                    cmd,
                    stdout=stdout,
                    stderr=stderr,
                    cwd=cwd,
                    check=True,
                    text=True
            )
        except subprocess.CalledProcessError as ex:
            log.error("Compile failed, exit code: %d" % ex.returncode)
            res = None

        stdout.close()
        stderr.close()

        if res is None or res.returncode != 0:
            # compile failed
            return False

        # compile succeeded
        return True

    def _pick_compiler(self, cc=None):
        """Returns the path to a C compiler on the system.

        Keyword Arguments:
        cc -- Optional user provided filepath. If None, this method will search
        the environment variables for a reasonable candidate.

        Returns:
        Path to compiler, or None if no candidate could be found.
        """
        if isinstance(cc, str) and os.path.isfile(os.path.realpath(cc)):
            # user provided a valid path to a file, let's trust them
            return cc

        c_compilers = ['gcc', 'clang']

        for comp in c_compilers:
            can = utils.find_bin(comp)
            if isinstance(can, str):
                return can

        return None

    def write_makefile(self, ofp, cmd):
        """Write a Makefile into ofile that'll execute cmd.

        Keyword Arguments:
        ofp -- Filepath to write Makefile to.
        cmd -- A list of the command and its arguments.
        """
        # escape each argument
        cmd = [arg.replace('"', '\\"') for arg in cmd]
        # wrap each argument
        cmd = ['"%s"' % arg for arg in cmd]

        # write Makefile
        with open(ofp, 'w') as ofile:
            ofile.write("all:\n\t%s\n" % ' '.join(cmd))