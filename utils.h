#define INTEL_RET_INSTRUCTION 0xc3
#define INTEL_INT3_INSTRUCTION 0xcc

size_t inject_target_snippet(pid_t pid, long addr, char *backup);
int checkstack(pid_t pid, long addr, char* libname);
pid_t findProcessByName(char* processName);
long freespaceaddr(pid_t pid);
long getSharedLibAddr(pid_t pid, char *libstr);
void getSharedLibPath(pid_t pid, char *libstr, char *libpath);
int checkloaded(pid_t pid, char* libname);
long getFunctionAddress(char* funcName);
unsigned char* findRet(void* endAddr);
void usage(char* name);
