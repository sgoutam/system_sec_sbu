
#include "pin.H"
#include <iostream>
#include <fstream>
#include <stack>
#include <unordered_map>
#include <iomanip>

using namespace std;

/* ================================================================== */
// Global variables
/* ================================================================== */

// Force each thread's data to be in its own data cache line so that
// multiple threads do not contend for the same data cache line.
// This avoids the false sharing problem.
#define PADSIZE 56 // 64 byte line size: 64-8

UINT64 threadCount = 0; //total number of threads, including main thread
UINT64 total_mismatch = 0;		// count total mismatch across all threads

class thread_data_t
{
	public:
		stack<ADDRINT> shadow_stack;
		bool mismatch;
		unordered_map<ADDRINT, int> hash_map;
		UINT8 _pad[PADSIZE];
};


// key for accessing TLS storage in each thread. initialize in main()
static TLS_KEY tls_key = INVALID_TLS_KEY;


std::ostream* out = &cerr;


/* ===================================================================== */
// Command line switches
/* ===================================================================== */
// override cerr with outfile
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "", "specify file name for MyPinTool output");


/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
*  Print out help message.
*/
INT32 Usage()
{
	cerr << "This tool creates shadow stacks for each thread of an application and records any mismatches in the call/returns" << endl;
	cerr << "Pass a binary as an argument" << endl;

	cerr << KNOB_BASE::StringKnobSummary() << endl;

	return -1;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */
VOID push_stack(ADDRINT target_addr, ADDRINT return_ip, THREADID thread_id)
{

	// Insert Return address into stack
	thread_data_t* tdata = static_cast< thread_data_t* >(PIN_GetThreadData(tls_key, thread_id));
	tdata->shadow_stack.push(return_ip);
}

VOID check_stack(ADDRINT instr_ptr, ADDRINT target_addr, THREADID thread_id)
{

	// Compare top of stack with branch target address of return

	thread_data_t* tdata = static_cast< thread_data_t* >(PIN_GetThreadData(tls_key, thread_id));
	if (tdata->shadow_stack.top() == target_addr)
	{
		tdata->shadow_stack.pop();
		// *out << "Top of stack matches with target_addr"  << endl;
	}
	else {
		// check the top 4 stack addresses

		// cerr << "Potential Stack attack detected " << endl;
		stack<ADDRINT> temp = tdata->shadow_stack;
		int i = 0;
		while (++i <= 4 && temp.top() != target_addr)
				temp.pop();

		if (i > 0 && i <= 4)
		{
			// cerr << "Return detected in top 4 of stack" << endl;
			// return address found between shadow_stack[0] and shadow_stack[3]
			while(--i > 0)
			{	
				// *out << "Shadow_stack pop" << endl;
				tdata->shadow_stack.pop();			// pop from shadow_stack i times
			}
		}
		else 
		{
			// cerr << "Inserting into Hash_map" << endl;
			if (tdata->hash_map.find(instr_ptr) == tdata->hash_map.end())		// first occurence
				tdata->hash_map.insert(make_pair(instr_ptr, 1));
			else 
				tdata->hash_map[instr_ptr]++;
			
			// cerr << "Hash_data: " << RTN_FindNameByAddress(instr_ptr) << " " << tdata->hash_map[instr_ptr] << endl;
			tdata->mismatch = TRUE;
			total_mismatch++;
		}
		// *out << "Mismatch detected with target_addr: " << target_addr << endl;
		// *out << "Top of the stack: " << shadow_stack.top() << endl;
	}

}



/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */


// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID* v)
{
	
	if ( INS_IsCall(ins) )
		INS_InsertCall(ins, IPOINT_TAKEN_BRANCH, (AFUNPTR)push_stack, 
						IARG_BRANCH_TARGET_ADDR, IARG_RETURN_IP, 
						IARG_THREAD_ID, IARG_END);
	
	if ( INS_IsRet(ins) )
		INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(check_stack), 
						IARG_INST_PTR, IARG_BRANCH_TARGET_ADDR, 
						IARG_THREAD_ID, IARG_END);
}



VOID ThreadStart(THREADID threadid, CONTEXT* ctxt, INT32 flags, VOID* v) 
{
	threadCount++;
	thread_data_t* tdata = new thread_data_t;
	if (PIN_SetThreadData(tls_key, tdata, threadid) == FALSE)
	{
		cerr << "PIN_SetThreadData failed" << endl;
		PIN_ExitProcess(1);
	}
	tdata->mismatch = FALSE;
}


VOID ThreadFini(THREADID threadIndex, const CONTEXT* ctxt, INT32 code, VOID* v)
{
	thread_data_t* tdata = static_cast< thread_data_t* >(PIN_GetThreadData(tls_key, threadIndex));

	if (tdata->mismatch)
	{
		*out << "===================================================================================" << endl;
		*out << "Thread ID: " << decstr(threadIndex) << endl;
		*out << setw(60) << "Function Name " << "|" << setw(10) << "Count" << endl;
		*out << "-----------------------------------------------------------------------------------" << endl;
		for (auto p : tdata->hash_map)
		{
			//cerr << RTN_FindNameByAddress(p.first) << " " << p.second << endl;
			*out << setw(60) << RTN_FindNameByAddress(p.first)  << "|" << setw(10) << p.second << endl;
		}
		*out << "=====================================================================================" << endl;
	}
	delete tdata;
}



VOID Fini(INT32 code, VOID* v)
{
	if (total_mismatch > 0)
	{
		*out << "Stack Smashing Detected in program" << endl;
		*out << "Total mismatches detected :" << total_mismatch << endl;

	}

}


int main(int argc, char* argv[])
{
	// Initialize PIN library. Print help message if -h(elp) is specified
	// in the command line or the command line is invalid
	if (PIN_Init(argc, argv))
	{
		return Usage();
	}

	PIN_InitSymbols();

	string fileName = KnobOutputFile.Value();

	if (!fileName.empty())
		{
			out = new std::ofstream(fileName.c_str());
		}

	// Obtain a key for TLS storage
	tls_key = PIN_CreateThreadDataKey(NULL);
	if (tls_key == INVALID_TLS_KEY)
	{
		cerr << "number of already allocated keys reached the MAX_CLIENT_TLS_KEYS limit" << endl;
		PIN_ExitProcess(1);
	}


	// Register function to be called for every thread before it starts running
	PIN_AddThreadStartFunction(ThreadStart, NULL);

	// Register function to be called when thread exits
	PIN_AddThreadFiniFunction(ThreadFini, NULL);

	// Register function to be called when the application exits
	PIN_AddFiniFunction(Fini, NULL);

	// Register function to be called to instrument instructions
	INS_AddInstrumentFunction(Instruction, NULL);


	cerr << "===============================================" << endl;
	cerr << "This application is instrumented by sanket_pintool_tls" << endl;
	cerr << "Generating analysis report for Backward-Edge CFI violations" << endl;
	if (!KnobOutputFile.Value().empty())
	{
		cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
	}
	cerr << "===============================================" << endl;


	// Start the program, never returns
	PIN_StartProgram();

	return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
