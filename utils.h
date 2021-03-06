#define INTEL_RET_INSTRUCTION 0xc3
#define INTEL_INT3_INSTRUCTION 0xcc

#include "list.h"
#include "ptrace.h"
struct symstr_list {
	char *string;
	struct list_head list;
};

void target_snippet(void);
void target_snippet_end(void);
int stop_tgt_threads(pid_t target);
int start_tgt_threads(pid_t target);
size_t inject_shared_library(pid_t target, char *new_libname,
		char *orig_libname);
int check_tgt_stack(pid_t pid, char *libname);
long get_tgt_funcaddr(pid_t target, char *funcname, char *libname);
pid_t find_proc_by_name(char *procname);
long get_base_addr(pid_t pid, char *libstr, long *len);
int get_proc_elfpath(pid_t pid, char **elfpath);
int get_libpath(pid_t pid, char *libstr, char **libpath);
unsigned char *find_ret_inst(void *endaddr);
void usage(char *name);
