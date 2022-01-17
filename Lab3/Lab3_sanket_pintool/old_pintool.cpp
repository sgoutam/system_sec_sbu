
#include "pin.H"
#include <iostream>
#include <fstream>
#include <stack>
#include <unordered_map>

using namespace std;

/* ================================================================== */
// Global variables
/* ================================================================== */

UINT64 threadCount = 0; //total number of threads, including main thread

// implement a shadow stack to keep a record of all return addresses for each call
stack<VOID*> shadow_stack;
unordered_map<VOID*, int> hash_map;

std::ostream* out = &cerr;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB< string > KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "MyPinTool.out", "specify file name for MyPinTool output");


/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
*  Print out help message.
*/
INT32 Usage()
{
	cerr << "This tool prints out the number of dynamically executed " << endl
			<< "instructions, basic blocks and threads in the application." << endl
			<< endl;

	cerr << KNOB_BASE::StringKnobSummary() << endl;

	return -1;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */
VOID push_stack(VOID* target_addr, VOID* return_ip, VOID* thread_id)
{
	/**out << "===============================================" << endl;
	*out << "Call analysis results: " << endl;
	*out << "Branch Target Address: " << target_addr << endl;
	*out << "Return address: " << return_ip << endl;
	*out << "Thread ID: " << thread_id << endl;
	*out << "===============================================" << endl;*/
	// Insert Return address into stack

	shadow_stack.push(return_ip);
}

VOID check_stack(VOID* instr_ptr, VOID* target_addr, VOID* thread_id)
{
	/**out << "===============================================" << endl;
	*out << "Return analysis results: " << endl;
	*out << "Instruction Pointer " << instr_ptr << endl;
	*out << "Branch Target Address: " << target_addr << endl;
	*out << "Thread ID: " << thread_id << endl;
	*out << "===============================================" << endl;*/

	// Compare top of stack with branch target address of return

	if (shadow_stack.top() == target_addr)
	{
		shadow_stack.pop();
		// *out << "Top of stack matches with target_addr"  << endl;
	}
	else {
		// check the top 4 stack addresses

		stack<VOID*> temp = shadow_stack;
		int i = 0;
		while (i < 4 && temp.top() != target_addr)
		{
				temp.pop();
				i++;
		}

		if (i > 0 && i < 4)
		{
			// return address found between shadow_stack[0] and shadow_stack[3]
			while(i-- > 0)
			{	
				// *out << "Shadow_stack pop" << endl;
				shadow_stack.pop();			// pop from shadow_stack i times
			}
		}
		else 
		{
			if (hash_map.find(target_addr) == hash_map.end())		// first occurence
				hash_map.insert(make_pair(target_addr, 1));
			else 
				hash_map[target_addr]++;
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



/*!
* Increase counter of threads in the application.
* This function is called for every thread created by the application when it is
* about to start running (including the root thread).
* @param[in]   threadIndex     ID assigned by PIN to the new thread
* @param[in]   ctxt            initial register state for the new thread
* @param[in]   flags           thread creation flags (OS specific)
* @param[in]   v               value specified by the tool in the 
*                              PIN_AddThreadStartFunction function call
*/
VOID ThreadStart(THREADID threadIndex, CONTEXT* ctxt, INT32 flags, VOID* v) { threadCount++; }

/*!
* Print out analysis results.
* This function is called when the application exits.
* @param[in]   code            exit code of the application
* @param[in]   v               value specified by the tool in the 
*                              PIN_AddFiniFunction function call
*/

VOID Fini(INT32 code, VOID* v)
{
	*out << "===============================================" << endl;
	*out << "MyPinTool analysis results " << endl;
	*out << "===============================================" << endl;
	*out << "Hash_Map for all the mismatches " << endl;
	unordered_map<VOID*, int>:: iterator p;
	for (p = hash_map.begin(); p != hash_map.end(); p++)
	{
		*out << "(" << p->first  << ", " << p->second << ")" << endl;
	}
	*out << "===============================================" << endl;


}

/*!
* The main procedure of the tool.
* This function is called when the application image is loaded but not yet started.
* @param[in]   argc            total number of elements in the argv array
* @param[in]   argv            array of command line arguments, 
*                              including pin -t <toolname> -- ...
*/
int main(int argc, char* argv[])
{
	// Initialize PIN library. Print help message if -h(elp) is specified
	// in the command line or the command line is invalid
	if (PIN_Init(argc, argv))
	{
			return Usage();
	}

	string fileName = KnobOutputFile.Value();

	if (!fileName.empty())
		{
			out = new std::ofstream(fileName.c_str());
		}

	PIN_InitSymbols();


	// Register function to be called to instrument instructions
	INS_AddInstrumentFunction(Instruction, 0);

	// Register function to be called for every thread before it starts running
	// PIN_AddThreadStartFunction(ThreadStart, 0);

	// Register function to be called when the application exits
	PIN_AddFiniFunction(Fini, 0);

	cerr << "===============================================" << endl;
	cerr << "This application is instrumented by MyPinTool" << endl;
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
