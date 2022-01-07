/* trace.c
 *
 * implements the fxn entry/exit monitoring functions
 * enabled with the gcc flag -finstrument-functions at compile
 * 
 * based on code originally written by Francesco Balducci and posted here: https://balau82.wordpress.com/2010/10/06/trace-and-profile-function-calls-with-gcc/
*/ 

// INCLUDES
#include <stdio.h>
#include <time.h>

static FILE *fp_trace;

// CONSTRUCTOR
// executed before program start
//// opens the trace file
void
__attribute__ ((constructor))
trace_begin (void)
{
 fp_trace = fopen("trace.out", "w");
}

// DESTRUCTOR
// executed before program exit
//// closes the trace file
void
__attribute__ ((destructor))
trace_end (void)
{
 if(fp_trace != NULL) {
 fclose(fp_trace);
 }
}

// __cyg_profile_func_enter
// called after function entry
//// writes the function addresses, the address of the call,
//// and the execution time into the trace file
void
__cyg_profile_func_enter (void *func,  void *caller)
{
 if(fp_trace != NULL) {
 fprintf(fp_trace, "e %p %p %lu\n", func, caller, time(NULL) );
 }
}

// __cyg_profile_func_exit
// called after function exit
//// writes the function addresses, the address of the call,
//// and the execution time into the trace file
void
__cyg_profile_func_exit (void *func, void *caller)
{
 if(fp_trace != NULL) {
 fprintf(fp_trace, "x %p %p %lu\n", func, caller, time(NULL));
 }
}