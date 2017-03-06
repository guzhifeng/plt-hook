#define INTEL_RET_INSTRUCTION 0xc3
#define INTEL_INT3_INSTRUCTION 0xcc

void target_snippet(void);
void target_snippet_end();
void inject_target_snippet(pid_t pid, long addr, char *backup, size_t codelen);
long getLibcFuncAddr(char *funcName);
size_t inject_shared_library(pid_t pid, char *libname, char *origLibName);
int checkstack(pid_t pid, long addr, char* libname);
long getTargetFuncAddr(pid_t target, char* funcname, char* libname);
pid_t findProcessByName(char* processName);
long freespaceaddr(pid_t pid);
int getProcessElfPath(pid_t pid, char *elfpath);
long getSharedLibAddr(pid_t pid, char *libstr);
void getSharedLibPath(pid_t pid, char *libstr, char *libpath);
int checkloaded(pid_t pid, char* libname);
long getFunctionAddress(char* funcName);
unsigned char* findRet(void* endAddr);
void usage(char* name);
