#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <wait.h>
#include <time.h>

#define REG_TYPE user_regs_struct

int ptrace_attach(pid_t target);
int ptrace_detach(pid_t target);
int ptrace_getregs(pid_t target, struct REG_TYPE* regs);
int ptrace_cont(pid_t target);
int ptrace_setregs(pid_t target, struct REG_TYPE* regs);
int ptrace_getsiginfo(pid_t target, siginfo_t *targetsig);
int ptrace_read(int pid, unsigned long addr, void *vptr, int len);
int ptrace_write(int pid, unsigned long addr, void *vptr, int len);
int checktargetsig(int pid);
