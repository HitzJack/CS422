#include "pin.H"
#include <iostream>
#include <fstream>
#include <string>

std::ofstream TraceFile;

// Function to print the instruction pointer and the disassembled instruction
VOID PrintInst(ADDRINT ip, std::string* disass) {
    TraceFile << std::hex << ip << " : " << *disass << std::endl;
}

// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID *v) {
    // We only care about instructions in the main executable (leaky_rsa)
    // This prevents our trace from being flooded with standard library setup operations.
    RTN rtn = INS_Rtn(ins);
    if (RTN_Valid(rtn)) {
        SEC sec = RTN_Sec(rtn);
        if (SEC_Valid(sec)) {
            IMG img = SEC_Img(sec);
            if (IMG_Valid(img) && IMG_IsMainExecutable(img)) {
                // Get the disassembled instruction string
                std::string* disass = new std::string(INS_Disassemble(ins));
                
                // Insert a call to PrintInst before every instruction in the main binary
                INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)PrintInst,
                               IARG_INST_PTR,
                               IARG_PTR, disass,
                               IARG_END);
            }
        }
    }
}

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v) {
    TraceFile.close();
}

int main(int argc, char * argv[]) {
    // Initialize PIN library. Print help message if -h(elp) is specified
    if (PIN_Init(argc, argv)) {
        std::cerr << "Command line error" << std::endl;
        return -1;
    }
    
    // Initialize symbols to safely access image information
    PIN_InitSymbols();

    // Open the output file
    TraceFile.open("trace.txt");

    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
