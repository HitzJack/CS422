#include "pin.H"
#include <iostream>
#include <fstream>
#include <set>
#include <map>
#include <chrono>
#include <iomanip>
#include <cstdlib>

using namespace std;

chrono::time_point<chrono::high_resolution_clock> startTime, endTime;

UINT64 fast_forward_count = 0;
UINT64 insCount = 0;    
UINT64 bblCount = 0;    
UINT64 threadCount = 0; 
UINT64 num_ins = 0;     
UINT64 num_loads = 0;
UINT64 num_stores = 0;
UINT64 num_nops = 0;
UINT64 num_direct_calls = 0;
UINT64 num_indirect_calls = 0;
UINT64 num_returns = 0;
UINT64 num_uncond_branches = 0;
UINT64 num_cond_branches = 0;
UINT64 num_logical_ops = 0;
UINT64 num_rotate_shifts = 0;
UINT64 num_flag_ops = 0;
UINT64 num_vec_ins = 0;
UINT64 num_cond_moves = 0;
UINT64 num_mmx_sse_ins = 0;
UINT64 num_sys_calls = 0;
UINT64 num_flops = 0;
UINT64 num_others = 0;

// Part C Tracking Single vs Multi Chunk accesses
UINT64 ins_single_chunk = 0;
UINT64 ins_multi_chunk = 0;
UINT64 data_single_chunk = 0;
UINT64 data_multi_chunk = 0;

// Use ADDRINT for 32-bit binary compatibility (still 32-bit but safer)
set<ADDRINT> instrAddr;
set<ADDRINT> dataAddr;
map<UINT32, UINT64> insLength; 
map<UINT32, UINT64> insOp; 
map<UINT32, UINT64> readReg; 
map<UINT32, UINT64> writeReg;
map<UINT32, UINT64> memOp;
map<UINT32, UINT64> memReadOp;
map<UINT32, UINT64> memWriteOp;

UINT32 maxMemBytes = 0;
UINT64 totalMemBytes = 0;
INT32 maxImm = INT32_MIN;
INT32 minImm = INT32_MAX;
ADDRDELTA maxDisp = INT32_MIN;
ADDRDELTA minDisp = INT32_MAX;

std::ostream *out = &cerr;
UINT64 total_ins = 0;

KNOB<BOOL> KnobCount(KNOB_MODE_WRITEONCE, "pintool", "count", "1", "count instructions, basic blocks and threads in the application");
KNOB<UINT64> KnobFastForward(KNOB_MODE_WRITEONCE, "pintool", "f", "0", "Fast-forward amount");
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "HW1.out", "specify output file name");

INT32 Usage()
{
    cerr << "This tool prints out the number of dynamically executed " << endl
         << "instructions, basic blocks and threads in the application." << endl
         << endl;
    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

VOID count_insbb(UINT32 x) { insCount += x; }
VOID count_loads(UINT32 x) {num_loads+=x; }
VOID count_stores(UINT32 x) {num_stores+=x;}
VOID count_nops() {num_nops++;}
VOID count_direct_calls() {num_direct_calls++;}
VOID count_indirect_calls() {num_indirect_calls++;}
VOID count_returns() { num_returns++; }
VOID count_uncond_branches() { num_uncond_branches++; }
VOID count_cond_branches() { num_cond_branches++; }
VOID count_logical_ops() { num_logical_ops++; }
VOID count_rotate_shifts() { num_rotate_shifts++; }
VOID count_flag_ops() { num_flag_ops++; }
VOID count_vec_ins() { num_vec_ins++; }
VOID count_cond_moves() { num_cond_moves++; }
VOID count_mmx_sse_ins() { num_mmx_sse_ins++; }
VOID count_sys_calls() { num_sys_calls++; }
VOID count_flops() { num_flops++; }
VOID count_others() { num_others++; }

ADDRINT Terminate(void) { return (insCount >= fast_forward_count + 1000000000); }
ADDRINT FastForward (void) { return ((insCount >= fast_forward_count) && (insCount < fast_forward_count + 1000000000)); }

// Part C: Instruction footprint - called for ALL instructions (not predicated)
// but only after fast-forward
VOID ins_footprint(ADDRINT insAddr, UINT32 insSize) {
    if (insSize == 0) return;
    ADDRINT startChunk = insAddr / 32;
    ADDRINT endChunk = (insAddr + insSize - 1) / 32;
    
    for (ADDRINT i = startChunk; i <= endChunk; ++i) {
        instrAddr.insert(i * 32);
    }
    
    if (startChunk == endChunk) ins_single_chunk++;
    else ins_multi_chunk++;
}

// Part C: Data footprint - called for memory instructions with true predicates
VOID data_footprint(ADDRINT memAddr, UINT32 memSize) {
    if (memSize == 0) return;
    ADDRINT startChunk = memAddr / 32;
    ADDRINT endChunk = (memAddr + memSize - 1) / 32;
    
    for (ADDRINT i = startChunk; i <= endChunk; ++i) {
        dataAddr.insert(i * 32);
    }
    
    if (startChunk == endChunk) data_single_chunk++;
    else data_multi_chunk++;
}

// Part D1-D4: Called for ALL instructions (not predicated) after fast-forward
VOID ins_distribution(
    UINT32 insSize, 
    UINT32 opCount, 
    UINT32 insReadReg, 
    UINT32 insWriteReg
){
    insLength[insSize]++;
    insOp[opCount]++;
    readReg[insReadReg]++; 
    writeReg[insWriteReg]++;
}

// Part D5-D8: Called for memory instructions with true predicates
VOID mem_distribution(
    UINT32 numRead, 
    UINT32 numWrite,
    UINT32 totalMemSize
){
    memOp[numRead+numWrite]++; 
    memReadOp[numRead]++; 
    memWriteOp[numWrite]++;
    if (totalMemSize > maxMemBytes) maxMemBytes = totalMemSize;
    totalMemBytes += totalMemSize;
}

// Part D9: Immediate distribution - called for ALL instructions after fast-forward
VOID imm_distribution(ADDRINT immValue){
    INT32 imm = (INT32) immValue;
    if (imm > maxImm) maxImm = imm;
    if (imm < minImm) minImm = imm;
}

// Part D10: Displacement distribution - called for memory instructions with true predicates
VOID disp_distribution(ADDRINT dispValue){
    ADDRDELTA disp = (ADDRDELTA) dispValue;
    if (disp > maxDisp) maxDisp = disp;
    if (disp < minDisp) minDisp = disp;
}

void PrintRow(const string &name, UINT64 count){
    double percentage = (total_ins == 0) ? 0.0 : (100.0 * count / total_ins);
    *out << left << setw(30) << name
         << setw(15) << count
         << setw(14) << fixed << setprecision(6) << percentage << "%" << endl;
}

void PrintResults(const string &title, const map<UINT32, UINT64> &data) {
    *out << title << " Results: " << endl;
    for (const auto &entry : data) {
        *out << entry.first << " : " << entry.second << endl;
    }
    *out << endl;
}

void MyExitRoutine() {
    // Calculate total Type A instructions
    total_ins = num_loads + num_stores + num_nops + num_direct_calls +
                num_indirect_calls + num_returns + num_uncond_branches +
                num_cond_branches + num_logical_ops + num_rotate_shifts +
                num_flag_ops + num_vec_ins + num_cond_moves +
                num_mmx_sse_ins + num_sys_calls + num_flops + num_others;
    
    // Calculate total instructions including Type B micro-operations
    UINT64 total_all_ins = total_ins + num_loads + num_stores;
    
    // Part D8: Calculate average memory bytes
    UINT64 memInsCount = 0;
    for(const auto &entry : memOp){
        if(entry.first > 0) memInsCount += entry.second;
    }
    double avgMemBytes = (memInsCount == 0) ? 0.0 : ((1.0*totalMemBytes) / memInsCount);

    *out << "============================================================" << endl;
    *out << "Part A Analysis Results: " << endl;
    *out << "------------------------------------------------------------" << endl;
    *out << "Total Instructions: " << insCount << endl;
    *out << "Total Instructions after fast forward: " << insCount - fast_forward_count << endl;
    *out << "------------------------------------------------------------" << endl;

    *out << left << setw(30) << "Instruction Type" << setw(15) << "Count" << setw(15) << "Percentage" << endl;
    *out << "------------------------------------------------------------" << endl;

    PrintRow("Loads", num_loads);
    PrintRow("Stores", num_stores);
    PrintRow("NOPs", num_nops);
    PrintRow("Direct Calls", num_direct_calls);
    PrintRow("Indirect Calls", num_indirect_calls);
    PrintRow("Returns", num_returns);
    PrintRow("Unconditional Branches", num_uncond_branches);
    PrintRow("Conditional Branches", num_cond_branches);
    PrintRow("Logical Operations", num_logical_ops);
    PrintRow("Rotate & Shift", num_rotate_shifts);
    PrintRow("Flag Operations", num_flag_ops);
    PrintRow("Vector Instructions", num_vec_ins);
    PrintRow("Conditional Moves", num_cond_moves);
    PrintRow("MMX & SSE Instructions", num_mmx_sse_ins);
    PrintRow("System Calls", num_sys_calls);
    PrintRow("Floating-Point", num_flops);
    PrintRow("Others", num_others);

    *out << "============================================================" << endl;
    *out << "Part B Analysis Results: " << endl;
    // FIXED: Use 70.0 instead of 69.0, and correct denominator
    double cpi = (70.0 * (num_loads + num_stores) + total_ins) / (double)total_all_ins;
    *out << "CPI = " << fixed << setprecision(6) << cpi << endl;

    *out << "============================================================" << endl;
    *out << "Part C Analysis Results: " << endl;
    *out << "------------------------------------------------------------" << endl;
    *out << "Instruction Footprint Blocks     = " << instrAddr.size() << endl;
    *out << "Instruction Footprint (in bytes) = " << 32*instrAddr.size() << endl;
    *out << "Data Footprint Blocks            = " << dataAddr.size() << endl;
    *out << "Data Footprint (in bytes)        = " << 32*dataAddr.size() << endl;
    
    UINT64 total_ins_chunks = ins_single_chunk + ins_multi_chunk;
    *out << "\nInstruction Accesses (Single Chunk)  : " << ins_single_chunk 
         << " (" << (total_ins_chunks ? 100.0 * ins_single_chunk / total_ins_chunks : 0.0) << "%)" << endl;
    *out << "Instruction Accesses (Multi Chunks)  : " << ins_multi_chunk 
         << " (" << (total_ins_chunks ? 100.0 * ins_multi_chunk / total_ins_chunks : 0.0) << "%)" << endl;

    UINT64 total_data_chunks = data_single_chunk + data_multi_chunk;
    *out << "Data Accesses (Single Chunk)         : " << data_single_chunk 
         << " (" << (total_data_chunks ? 100.0 * data_single_chunk / total_data_chunks : 0.0) << "%)" << endl;
    *out << "Data Accesses (Multi Chunks)         : " << data_multi_chunk 
         << " (" << (total_data_chunks ? 100.0 * data_multi_chunk / total_data_chunks : 0.0) << "%)" << endl;

    *out << "============================================================" << endl;
    *out << "Part D Analysis Results: " << endl;
    *out << "------------------------------------------------------------" << endl;

    PrintResults("1. Instruction Size Distribution", insLength);
    PrintResults("2. Instruction Operand Distribution", insOp);
    
    // Explicitly requested single values for D3 - D7
    *out << "3. Instructions with 2 register read operands : " << readReg[2] << endl;
    *out << "4. Instructions with 1 register write operand : " << writeReg[1] << endl;
    *out << "5. Instructions with 3 memory operands        : " << memOp[3] << endl;
    *out << "6. Instructions with 1 memory read operand    : " << memReadOp[1] << endl;
    *out << "7. Instructions with 2 memory write operands  : " << memWriteOp[2] << endl;
    *out << endl;

    *out << "8. Maximum memory bytes touched by an instruction : " << maxMemBytes << endl;
    *out << "   Average memory bytes touched by an instruction : " << fixed << setprecision(6) << avgMemBytes << endl;
    *out << "9. Maximum value of immediate                   : " << maxImm << endl;
    *out << "   Minimum value of immediate                   : " << minImm << endl;
    *out << "10. Maximum value of displacement                : " << maxDisp << endl;
    *out << "   Minimum value of displacement                : " << minDisp << endl;
    
    endTime = chrono::high_resolution_clock::now();
    chrono::duration<double> elapsed = endTime - startTime;
    *out << "Time taken : " << elapsed.count() << " seconds." << endl;
    
    // Clean up
    if (out != &cerr) {
        delete out;
    }
    
    exit(0);
}

VOID Trace(TRACE trace, VOID *v)
{
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl)) {
        // Termination check at BBL level
        BBL_InsertIfCall(bbl, IPOINT_BEFORE, (AFUNPTR) Terminate, IARG_END);
        BBL_InsertThenCall(bbl, IPOINT_BEFORE, (AFUNPTR)MyExitRoutine, IARG_END);
        
        // Count instructions (unconditional)
        BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)count_insbb, IARG_UINT32, BBL_NumIns(bbl), IARG_END);
        
        for(INS ins=BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins)){
            
            ADDRINT insAddr = INS_Address(ins);
            UINT32 insSize = INS_Size(ins);
            
            // Part C: Instruction footprint - for ALL instructions after fast-forward
            // Use InsertThenCall (not predicated) because even false predicated instructions are fetched
            INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
            INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)ins_footprint, 
                              IARG_ADDRINT, insAddr, 
                              IARG_UINT32, insSize, 
                              IARG_END);

            // Part D1-D4: Instruction distribution - for ALL instructions after fast-forward
            UINT32 opCount = INS_OperandCount(ins);
            UINT32 insReadReg = INS_MaxNumRRegs(ins);
            UINT32 insWriteReg = INS_MaxNumWRegs(ins);
            
            INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
            INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)ins_distribution, 
                            IARG_UINT32, insSize, 
                            IARG_UINT32, opCount, 
                            IARG_UINT32, insReadReg, 
                            IARG_UINT32, insWriteReg, 
                            IARG_END);

            // Part D9: Immediate values - for ALL instructions after fast-forward
            UINT32 operandCount = INS_OperandCount(ins);
            for (UINT32 opIdx = 0; opIdx < operandCount; opIdx++) {
                if (INS_OperandIsImmediate(ins, opIdx)) {
                    INT32 immValue = INS_OperandImmediate(ins, opIdx);
                    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
                    INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)imm_distribution, 
                                      IARG_ADDRINT, (ADDRINT)immValue, 
                                      IARG_END);
                }
            }

            // Process memory operands
            UINT32 memOperands = INS_MemoryOperandCount(ins);
            UINT32 numRead = 0, numWrite = 0;
            UINT32 totalMemSize = 0;

            for (UINT32 memOper = 0; memOper < memOperands; memOper++)
            {
                UINT32 memSize = INS_MemoryOperandSize(ins, memOper);
                // Calculate number of 32-bit chunks
                UINT32 numChunks = (memSize + 3) / 4;  // Equivalent to ceil(memSize/4)
                
                if (INS_MemoryOperandIsRead(ins, memOper)){
                    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
                    INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)count_loads, 
                                                IARG_UINT32, numChunks, 
                                                IARG_END);
                    numRead++;
                }
                if (INS_MemoryOperandIsWritten(ins, memOper)){  
                    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
                    INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)count_stores, 
                                                IARG_UINT32, numChunks, 
                                                IARG_END);
                    numWrite++;
                }
                
                // Part D10: Displacement - for memory instructions with true predicates
                // FIXED: Convert memory operand index to operand index
                if (INS_OperandIsMemory(ins, memOper)) {
                    UINT32 operandIdx = INS_MemoryOperandIndexToOperandIndex(ins, memOper);
                    ADDRDELTA displacement = INS_OperandMemoryDisplacement(ins, operandIdx);
                    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
                    INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)disp_distribution, 
                                                IARG_ADDRINT, (ADDRINT)displacement, 
                                                IARG_END);
                }
                
                // Part C: Data footprint - FIXED: Use IARG_MEMORYOP_EA for runtime address
                INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)data_footprint, 
                                            IARG_MEMORYOP_EA, memOper,  // FIXED: Runtime address
                                            IARG_UINT32, memSize, 
                                            IARG_END);
                totalMemSize += memSize;
            }

            // Part D5-D8: Memory distribution - for memory instructions with true predicates
            if (memOperands > 0) {
                INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)mem_distribution,  
                                    IARG_UINT32, numRead, 
                                    IARG_UINT32, numWrite,
                                    IARG_UINT32, totalMemSize,
                                    IARG_END);
            }

            // Part A: Type A instruction classification
            // This counts the computational part of ALL instructions (including Type B)
            // Must use predicated call as per assignment
            
            // IMPORTANT: We count Type A for ALL instructions, including those with memory operands
            // The "Others" category includes the computational part of Type B instructions
            
            if (INS_Category(ins) == XED_CATEGORY_NOP) {
                INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)count_nops, IARG_END);
            }
            else if (INS_Category(ins) == XED_CATEGORY_CALL) {
                if (INS_IsDirectCall(ins)) {
                    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
                    INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)count_direct_calls, IARG_END);
                }
                else {
                    INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
                    INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)count_indirect_calls, IARG_END);
                }
            }
            else if (INS_Category(ins) == XED_CATEGORY_RET) {
                INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)count_returns, IARG_END);
            }
            else if (INS_Category(ins) == XED_CATEGORY_UNCOND_BR) {
                INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)count_uncond_branches, IARG_END);
            }
            else if (INS_Category(ins) == XED_CATEGORY_COND_BR) {
                INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)count_cond_branches, IARG_END);
            }
            else if (INS_Category(ins) == XED_CATEGORY_LOGICAL) {
                INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)count_logical_ops, IARG_END);
            }
            else if (INS_Category(ins) == XED_CATEGORY_ROTATE || INS_Category(ins) == XED_CATEGORY_SHIFT) {
                INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)count_rotate_shifts, IARG_END);
            }
            else if (INS_Category(ins) == XED_CATEGORY_FLAGOP) {
                INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)count_flag_ops, IARG_END);
            }
            else if (INS_Category(ins) == XED_CATEGORY_AVX || INS_Category(ins) == XED_CATEGORY_AVX2 || 
                INS_Category(ins) == XED_CATEGORY_AVX2GATHER || INS_Category(ins) == XED_CATEGORY_AVX512) {
                INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)count_vec_ins, IARG_END);
            }
            else if (INS_Category(ins) == XED_CATEGORY_CMOV) {
                INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)count_cond_moves, IARG_END);
            }
            else if (INS_Category(ins) == XED_CATEGORY_MMX || INS_Category(ins) == XED_CATEGORY_SSE) {
                INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)count_mmx_sse_ins, IARG_END);
            }
            else if (INS_Category(ins) == XED_CATEGORY_SYSCALL) {
                INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)count_sys_calls, IARG_END);
            }
            else if (INS_Category(ins) == XED_CATEGORY_X87_ALU) {
                INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)count_flops, IARG_END);
            }
            else {
                // This includes the computational part of Type B instructions
                INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)FastForward, IARG_END);
                INS_InsertThenPredicatedCall(ins, IPOINT_BEFORE, (AFUNPTR)count_others, IARG_END);
            }
        }
    }
}

VOID Fini(INT32 code, VOID *v)
{
    MyExitRoutine();
}

int main(int argc, char *argv[])
{   
    startTime = chrono::high_resolution_clock::now();
    if (PIN_Init(argc, argv))
    {
        return Usage();
    }

    string fileName = KnobOutputFile.Value();
    fast_forward_count = KnobFastForward.Value() * 1000000000ULL; // Convert billions to actual count

    if (!fileName.empty())
    {
        out = new std::ofstream(fileName.c_str());
        if (!out->good()) {
            cerr << "Error: Could not open output file " << fileName << endl;
            delete out;
            out = &cerr;
        }
    }

    if (KnobCount)
    {
        TRACE_AddInstrumentFunction(Trace, 0);
        PIN_AddFiniFunction(Fini, 0);
    }

    cerr << "===============================================" << endl;
    cerr << "Results of instrumenting the given binary:" << endl;
    if (!KnobOutputFile.Value().empty())
    {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }
    cerr << "===============================================" << endl;

    PIN_StartProgram();

    return 0;
}
