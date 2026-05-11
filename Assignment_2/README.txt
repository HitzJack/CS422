=========================================================
CS422 Assignment: RSA Square and Multiply PIN Tool Attack
=========================================================

This submission contains an automated exploit chain that uses Intel PIN to perform a dynamic side-channel execution attack on a vulnerable RSA "Square and Multiply" implementation. It automatically traces instructions, extracts the 64-bit secret key completely independent of operands or ASLR, and verifies it against the target binary. For the leaky_rsa binary given to our group, the key was found to be 2753 in decimal representation.

FILES INCLUDED:
---------------
1. rsa_attack.cpp : The Intel PIN instrumentation tool source code.
2. extract_key.py : The Python script that parses the trace and extracts the key.
3. auto_crack.sh  : The bash wrapper script that automates the exploit.
4. README.txt     : These instructions.

PHASE 1: SETUP & COMPILATION
----------------------------
Because Intel PIN relies on specific internal Makefiles, these tools must be compiled from within the PIN directory structure.

1. Navigate to your Intel PIN installation directory.
2. Copy the submission files into the ManualExamples folder:
   cp rsa_attack.cpp extract_key.py auto_crack.sh /path/to/pin/source/tools/ManualExamples/
3. Navigate to that folder and compile the 64-bit tool:
   cd /path/to/pin/source/tools/ManualExamples/
   mkdir -p obj-intel64
   make obj-intel64/rsa_attack.so TARGET=intel64

*KNOWN GCC COMPATIBILITY NOTE:*
If the `make` command fails with a strict template error related to `range.hpp:102` (e.g., "no member named 'm_base'"), this is a known compatibility issue between newer GCC versions and the PIN framework's source code. 
To fix this, edit `../../../extras/components/include/util/range.hpp` around line 102 and change `range.m_base` to `range._base`. Re-run the `make` command.

PHASE 2: AUTOMATED EXECUTION
----------------------------
To execute the exploit, use the provided bash script.

1. Ensure the script is executable:
   chmod +x auto_crack.sh

2. Run the script and pass the path to the target vulnerable binary as the argument:
   ./auto_crack.sh /path/to/leaky_rsa

The script will automatically:
- Delete any old artifacts.
- Run the target through the PIN tool to generate `trace.txt`.
- Execute `extract_key.py` to parse the trace and identify the differential execution paths (counting multiplications between bit tests).
- Write the extracted decimal key to a single line in `key.txt`.
- Feed the key back into the target binary using the `-a` flag for verification.
