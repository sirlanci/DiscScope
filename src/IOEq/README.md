## How to run IOEq test
Below, you can find a few examples to run IOEq test. You should first run DiscScope with the examples given in DiscScope readme file to produce the `decompiled.o` object files.

Examples for GCC -O0 binaries

- `python3 IO_compare.py -f jas_iccprof_copy -d angr -o ../DiscScope/Bins/gcc_O0/Set1#jasper-1.900.16#jas_icc.o#gcc#O0#.o -r ../DiscScope/out/angr/Set1#jasper-1.900.16#jas_icc.o#gcc#O0#.o/jas_iccprof_copy/decompiled.o`

- `python3 IO_compare.py -f coff_read_word -d angr -o ../DiscScope/Bins/gcc_O0/Set1#binutils-2.29#pei-x86_64.o#gcc#O0#.o -r ../DiscScope/out/angr/Set1#binutils-2.29#pei-x86_64.o#gcc#O0#.o/coff_read_word/decompiled.o`

- `python3 IO_compare.py -f smiensure_buffer_stack -d angr -o ../DiscScope/Bins/gcc_O0/Set1#libsmi-0.4.8#scanner-smi.o#gcc#O0#.o -r ../DiscScope/out/angr/Set1#libsmi-0.4.8#scanner-smi.o#gcc#O0#.o/smiensure_buffer_stack/decompiled.o`

Examples for Clang -O0 binaries

- `python3 IO_compare.py -f jas_iccprof_copy -d angr -o ../DiscScope/Bins/clang_O0/Set1#jasper-1.900.16#jas_icc.o#clang#O0#.o -r ../DiscScope/out/angr/Set1#jasper-1.900.16#jas_icc.o#clang#O0#.o/jas_iccprof_copy/decompiled.o`

- `python3 IO_compare.py -f coff_read_word -d angr -o ../DiscScope/Bins/clang_O0/Set1#binutils-2.29#pei-x86_64.o#clang#O0#.o -r ../DiscScope/out/angr/Set1#binutils-2.29#pei-x86_64.o#clang#O0#.o/coff_read_word/decompiled.o`

- `python3 IO_compare.py -f smiensure_buffer_stack -d angr -o ../DiscScope/Bins/clang_O0/Set1#libsmi-0.4.8#scanner-smi.o#clang#O0#.o -r ../DiscScope/out/angr/Set1#libsmi-0.4.8#scanner-smi.o#clang#O0#.o/smiensure_buffer_stack/decompiled.o`

## Output of analysis
- `out/terminal_log/`: Contains analysis output shown on terminal
- `IO_analysis.log`: Contains the results per analysis in each line
