## 1. Structure of Repository

This repository has the following structure:
- `Bins/`: Contains set of binaries for GCC and Clang with 7 optimizations levels. We removed the malware binaries from the datasets to avoid any misuse.
- `decompilers/`: Contains Ida Pro and Ghidra installation folders. Since Ida Pro requires licence and Ghidra requires installation from scratch, they are not available as a part of this repository. 
- `out/`: Contains set of outputs from analysis.
- `src/`: Contains all the codes of the tool
- `src/IOEq`: Contains our implementation of Input/Output Equivalency using symbolic execution.


## 2. Environment Setup

- Install the required Linux packages. Run below command for installation:

`./install.sh` 

- Create a python virtual environment:

`pip -m venv venv`
`source venv/bin/activate`

- Run below command to install the required Python modules:

`pip install -r requirements.txt`

- Testing three decompilers (Ida Pro, Ghidra, Angr)

<strong>Ida Pro</strong>: To test Ida Pro decompiler, if you have Ida Pro 7.6, place the installation folder of Ida Pro under `decompilers/`. Then, make sure Ida Pro can run properly.

<strong>Ghidra</strong>: To test Ghidra decompiler, follow the installation instructions from `https://ghidra-sre.org/InstallationGuide.html` and place the installation folder of Ghidra under `decompilers/`.

<strong>Angr</strong>: After installing the python requirements, you will have Angr decompiler ready to test. No extra steps needed.  

## 3. How to Run Analysis
Since Ida Pro requires licence and Ghidra requires installation from the scratch, below below examples are given using Angr. Angr decompiler will be available with the installation of required Python modules. If you place the installation folders of Ida Pro and Ghidra under `decompilers/`, you can test those two decompilers by just modifying the `--decompiler` parameter in the commands below.

Example analysis for GCC -O0 binaries
- `python3 src/decompile.py -n jas_iccprof_copy --decompiler Angr Bins/gcc_O0/Set1#jasper-1.900.16#jas_icc.o#gcc#O0#.o`

	Output: Recompilation error

- `python3 src/decompile.py -n coff_read_word --decompiler Angr Bins/gcc_O0/Set1#binutils-2.29#pei-i386.o#gcc#O0#.o`

	Output: Functions diverged

- `python3 src/decompile.py -n smiensure_buffer_stack --decompiler Angr Bins/gcc_O0/Set1#libsmi-0.4.8#scanner-smi.o#gcc#O0#.o`

	Output: Functions are equivalent

Example analysis for Clang -O0 binaries
- `python3 src/decompile.py -n jas_iccprof_copy --decompiler Angr Bins/clang_O0/Set1#jasper-1.900.16#jas_icc.o#clang#O0#.o`

	Output: Recompilation error

- `python3 src/decompile.py -n coff_read_word --decompiler Angr Bins/clang_O0/Set1#binutils-2.29#pei-i386.o#clang#O0#.o`

	Output: Functions diverged

- `python3 src/decompile.py -n smiensure_buffer_stack --decompiler Angr Bins/clang_O0/Set1#libsmi-0.4.8#scanner-smi.o#clang#O0#.o`

	Output: Functions are equivalent

## 4. Output of Analysis

The `out` folder stores all the output files from analysis, including files (decompilation output text file, binary object file, variable definitions text file, etc.) produced during analysis, the data collected during analysis, log output of our tool from analysis, and recompilation errors. Below, we share the folder structure for `out`:
	
- `out/angr`: The artifacts obtained during an analysis with Angr 
- `out/ghidra/`: The artifacts obtained during an analysis with Ghidra 
- `out/ida/`: The artifacts obtained during an analysis with Ida Pro
- `out/json_log/`: Contains the json files storing the data collected during analysis
- `out/terminal_log/`: Contains analysis output shown on terminal (mostly for debugging purpose)
- `out/std`: contains the recompilation errors obtained during recompilation process
