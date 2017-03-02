#include <stdio.h>
#include <stdlib.h>
#include <dirent.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <math.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "elf_hook.h"
#include "utils.h"
#include "ptrace.h"

void target_snippet(void) { 
	asm("push %r9 \n"
	"callq *%r9 \n"
	"pop %r9 \n"
	);
}

void target_snippet_end() {
}

void inject_target_snippet(pid_t pid, long addr, char *backup, size_t codelen)
{
	intptr_t target_snippet_ret;
	char *newcode;

	/* also figure out where the RET instruction at the end of
	 * target_snippet() lies and overwrite it with an INT 3
	 * in order to break back into the target process. note that on x64,
	 * gcc force function addresses to be word-aligned,
	 * which means that functions are padded with NOPs. as a result, even
	 * though we've found the length of the function, it is very likely
	 * padded with NOPs, so we need to actually search to find the RET.
	 */
	target_snippet_ret = (intptr_t)findRet(target_snippet_end) -
		(intptr_t)target_snippet;

	/* back up whatever data at the address we want to modify. */
	ptrace_read(pid, addr, backup, codelen);

	/* set up a buffer and copy target_snippet() code into the
	 * target process.
	 */
	newcode = calloc(1, codelen * sizeof(char));
	memcpy(newcode, target_snippet, codelen - 1);
	/* overwrite the RET instruction with an INT 3. */
	newcode[target_snippet_ret] = INTEL_INT3_INSTRUCTION;

	/* copy target_snippet()'s code to the target address inside the
	 * target process' address space.
	 */
	ptrace_write(pid, addr, newcode, codelen);
	free(newcode);
}

size_t inject_shared_library(pid_t target, char *newLibName, char *origLibName)
{
	char *libPath;
	int libPathLength;
	pid_t mypid = 0;
	long mylibcaddr, targetLibcAddr;
	long mallocAddr, freeAddr, dlopenAddr;
	long mallocOffset, freeOffset, dlopenOffset;
	long targetMallocAddr, targetFreeAddr, targetDlopenAddr;
	struct user_regs_struct oldregs, regs;
	struct user_regs_struct target_regs;
	long addr, curr;
	size_t target_snippet_size;
	unsigned long long targetBuf;
	unsigned long long libAddr;
	char *backup;
	int error = 0;

	libPath = realpath(newLibName, NULL);

	if (!libPath) {
		fprintf(stderr, "can't find file \"%s\"\n", newLibName);
		return 1;
	}

	libPathLength = strlen(libPath) + 1;

	mypid = getpid();
	mylibcaddr = getSharedLibAddr(mypid, "libc-");
	targetLibcAddr = getSharedLibAddr(target, "libc-");

	/* find the addresses of the syscalls that we'd like to use inside the
	 * target, as loaded inside THIS process (i.e. NOT the target process)
	 * use the base address of libc to calculate offsets for the syscalls
	 * we want to use
	 */

	mallocAddr = getFunctionAddress("malloc");
	freeAddr = getFunctionAddress("free");
	dlopenAddr = getFunctionAddress("__libc_dlopen_mode");

	mallocOffset = mallocAddr - mylibcaddr;
	freeOffset = freeAddr - mylibcaddr;
	dlopenOffset = dlopenAddr - mylibcaddr;

	/* get the target process' libc function address */
	targetMallocAddr = targetLibcAddr + mallocOffset;
	targetFreeAddr = targetLibcAddr + freeOffset;
	targetDlopenAddr = targetLibcAddr + dlopenOffset;

	memset(&oldregs, 0, sizeof(struct user_regs_struct));
	memset(&regs, 0, sizeof(struct user_regs_struct));

	ptrace_attach(target);
	ptrace_getregs(target, &oldregs);
	memcpy(&regs, &oldregs, sizeof(struct user_regs_struct));

	/* check the stack activeness */
	curr = oldregs.rip;
	if (!checkstack(target, oldregs.rip, origLibName)) {
		ptrace_detach(target);
		return 1;
	}

	/* find a good address and copy target_snippet() to it*/
	addr = freespaceaddr(target) + sizeof(long);
	target_snippet_size = (intptr_t)target_snippet_end -
		(intptr_t)target_snippet;
	backup = calloc(1, target_snippet_size * sizeof(char));
	inject_target_snippet(target, addr, backup, target_snippet_size);

	/* set the target's rip to it. we have to advance by 2 bytes here
	 * because rip gets incremented by the size of the current instruction,
	 * and the instruction at the start of the function to inject always
	 * happens to be 2 bytes long.
	 *
	 * accroding to x64 calling convention, arguments are passed via REGs
	 * rdi, rsi, rdx, rcx, r8, and r9. see comments in target_snippet()
	 * for more details.
	 */
	regs.rip = addr + 2;
	regs.r9 = targetMallocAddr;
	regs.rdi = libPathLength;
	ptrace_setregs(target, &regs);

	/* call malloc() */
	ptrace_cont(target);

	/* the target process malloc() returns. check wether it succeeded */
	memset(&target_regs, 0, sizeof(struct user_regs_struct));
	ptrace_getregs(target, &target_regs);
	targetBuf = target_regs.rax;
	if (targetBuf == 0) {
		error = 1;
		fprintf(stderr, "malloc() failed to allocate memory\n");
		goto end;
	}

	/* malloc() succeeded, copy path of shared lib into the malloc'd
	 * buffer. 
	 */
	ptrace_write(target, targetBuf, libPath, libPathLength);

	/* continue the target's execution and call __libc_dlopen_mode. */
	regs.rip = addr + 2;
	regs.r9 = targetDlopenAddr;
	regs.rdi = targetBuf;
	regs.rsi = 1;

	ptrace_setregs(target, &regs);
	ptrace_cont(target);

	memset(&target_regs, 0, sizeof(struct user_regs_struct));
	ptrace_getregs(target, &target_regs);
	libAddr = target_regs.rax;

	/* if rax is 0 here, dlopen() failed, bail out cleanly. */
	if (libAddr == 0) {
		error = 1;
		fprintf(stderr, "dlopen() failed to load %s\n", newLibName);
		goto end;
	}

	/* now check /proc/pid/maps to see whether injection succecced. */
	if (checkloaded(target, newLibName))
		printf("\"%s\" successfully injected\n", newLibName);
	else {
		error = 1;
		fprintf(stderr, "could not inject \"%s\"\n", newLibName);
		goto end;
	}

	/* call free() and we don't care whether this succeeds, so don't
	 * bother checking the return value.
	 */
	regs.rip = addr + 2;
	regs.r9 = targetFreeAddr;
	regs.rdi = targetBuf;
	ptrace_setregs(target, &regs);
	ptrace_cont(target);

end:
	/* restore the old state and detach from the target. */
	restoreStateAndDetach(target, addr, backup,
			target_snippet_size, oldregs);
	free(backup);
	return error;
}
/*
 * checkstack()
 *
 * Check the target stack frame to make sure it is safe to replace the function.
 *
 * args:
 * - pid_t pid: process ID of the target process.
 * - long addr: address where target process's instruction register point at.
 * - char* libame: name of the shared library to be replaced.
 *
 * returns:
 * - a pid_t containing the pid of the process (or -1 if not found)
 *
 */
int checkstack(pid_t pid, long addr, char* libname)
{
	long func_addr, func_size;
	char libpath[PATH_MAX];
	long libAddr;
	int desc;

	/* read function length in .dynsym */
	Elf_Shdr *dynsym = NULL;
	Elf_Sym *symbol = NULL;
	char* name = "libsample";
	size_t name_index;

	getSharedLibPath(pid, libname, libpath);
	libAddr = getSharedLibAddr(pid, libname);
	desc = open(libpath, O_RDONLY);
	if (desc < 0) {
		fprintf(stderr, "can't open \"%s\"\n", libpath);
		return 0;
	}

 	/* get symbol named "name" in the ".dynsym" section */
	if (section_by_type(desc, SHT_DYNSYM, &dynsym) ||
	symbol_by_name(desc, dynsym, name, &symbol, &name_index)) {
		close(desc);
		return 0;
	}

	func_addr = libAddr + symbol->st_value;
	func_size = symbol->st_size;
	
	if ((addr >= func_addr) && (addr <= func_addr + func_size)) {
		printf("stack safety check failed for \"%d\"\n", pid);
	}

	close(desc);
	return 1;
}

/*
 * findProcessByName()
 *
 * Given the name of a process, try to find its PID by searching through /proc
 * and reading /proc/[pid]/exe until we find a process whose name matches the
 * given process.
 *
 * args:
 * - char* processName: name of the process whose pid to find
 *
 * returns:
 * - a pid_t containing the pid of the process (or -1 if not found)
 *
 */

pid_t findProcessByName(char *processName)
{
	DIR *directory;
	struct dirent *procDirs;
	int exePathLen;
	char *exePath, *exeBuf;
	ssize_t len;
	char *exeName, *exeToken;

	if (processName == NULL)
		return -1;

	directory = opendir("/proc/");

	if (directory) {
		while ((procDirs = readdir(directory)) != NULL) {
			if (procDirs->d_type != DT_DIR)
				continue;

			pid_t pid = atoi(procDirs->d_name);

			exePathLen = 10 + strlen(procDirs->d_name) + 1;
			exePath = malloc(exePathLen * sizeof(char));

			if (exePath == NULL)
				continue;

			sprintf(exePath, "/proc/%s/exe", procDirs->d_name);
			exePath[exePathLen-1] = '\0';

			exeBuf = malloc(PATH_MAX * sizeof(char));
			if (exeBuf == NULL) {
				free(exePath);
				continue;
			}

			len = readlink(exePath, exeBuf, PATH_MAX - 1);
			if (len == -1) {
				free(exePath);
				free(exeBuf);
				continue;
			}

			exeBuf[len] = '\0';

			exeName = NULL;
			exeToken = strtok(exeBuf, "/");
			while (exeToken) {
				exeName = exeToken;
				exeToken = strtok(NULL, "/");
			}

			if (strcmp(exeName, processName) == 0) {
				free(exePath);
				free(exeBuf);
				closedir(directory);
				return pid;
			}

			free(exePath);
			free(exeBuf);
		}

		closedir(directory);
	}

	return -1;
}

/*
 * freespaceaddr()
 *
 * Search the target process' /proc/pid/maps entry and find an executable
 * region of memory that we can use to run code in.
 *
 * args:
 * - pid_t pid: pid of process to inspect
 *
 * returns:
 * - a long containing the address of an executable region of memory inside the
 *   specified process' address space.
 *
 */

long freespaceaddr(pid_t pid)
{
	FILE *fp;
	char filename[30];
	char line[850];
	long addr;
	char str[20];
	char perms[5];

	sprintf(filename, "/proc/%d/maps", pid);

	fp = fopen(filename, "r");
	if (fp == NULL)
		exit(1);

	while (fgets(line, 850, fp) != NULL) {
		sscanf(line, "%lx-%*lx %s %*s %s %*d", &addr, perms, str);
		if (strstr(perms, "x") != NULL)
			break;
	}

	fclose(fp);
	return addr;
}

/*
 * getSharedLibAddr()
 *
 * Gets the base address of libc.so inside a process by reading /proc/pid/maps.
 *
 * args:
 * - pid_t pid: pid of the process whose libc.so base address we'd like to find
 * - char *libstr : subset string of the shared library name
 *
 * returns:
 * - a long containing the base address of libc.so inside that process
 *
 */

long getSharedLibAddr(pid_t pid, char *libstr)
{
	FILE *fp;
	char filename[30];
	char line[850];
	long addr;

	sprintf(filename, "/proc/%d/maps", pid);

	fp = fopen(filename, "r");
	if (fp == NULL)
		exit(1);

	while (fgets(line, 850, fp) != NULL) {
		sscanf(line, "%lx-%*lx %*s %*s %*s %*d %*s", &addr);
		if (strstr(line, libstr) != NULL)
			break;
	}

	fclose(fp);
	return addr;
}

/*
 * getSharedLibPath()
 *
 * Gets the name of original lib by reading /proc/pid/maps.
 *
 * args:
 * - pid_t pid: pid of the process we'd like to find
 * - char *libstr: Original function to be replaced
 *
 * returns:
 * - a long containing the base address of libc.so inside that process
 *
 */

void getSharedLibPath(pid_t pid, char *libstr, char *libpath)
{
	FILE *fp;
	char filename[30];
	char line[850];
	int len;

	sprintf(filename, "/proc/%d/maps", pid);

	fp = fopen(filename, "r");
	if (fp == NULL)
		exit(1);

	while (fgets(line, 850, fp) != NULL) {
		sscanf(line, "%*lx-%*lx %*s %*s %*s %*d %s", libpath);
		if (strstr(line, libstr) != NULL)
			break;
	}

	len = strlen(libpath);
	libpath[len] = '\0';

	fclose(fp);
}

/*
 * checkloaded()
 *
 * Given a process ID and the name of a shared library, check whether that
 * process has loaded the shared library by reading entries in its
 * /proc/[pid]/maps file.
 *
 * args:
 * - pid_t pid: the pid of the process to check
 * - char* libname: the library to search /proc/[pid]/maps for
 *
 * returns:
 * - an int indicating whether or not the library has been loaded into the
 *   process (1 = yes, 0 = no)
 *
 */

int checkloaded(pid_t pid, char *libname)
{
	FILE *fp;
	char filename[30], line[850];
	long addr;

	sprintf(filename, "/proc/%d/maps", pid);

	fp = fopen(filename, "r");
	if (fp == NULL)
		exit(1);

	while (fgets(line, 850, fp) != NULL) {
		sscanf(line, "%lx-%*lx %*s %*s %*s %*d", &addr);
		if (strstr(line, libname) != NULL) {
			fclose(fp);
			return 1;
		}
	}

	fclose(fp);
	return 0;
}

/*
 * getFunctionAddress()
 *
 * Find the address of a function within our own loaded copy of libc.so.
 *
 * args:
 * - char* funcName: name of the function whose address we want to find
 *
 * returns:
 * - a long containing the address of that function
 *
 */

long getFunctionAddress(char *funcName)
{
	void *self, *funcAddr;

	self = dlopen("libc.so.6", RTLD_LAZY);
	funcAddr = dlsym(self, funcName);

	return (long)funcAddr;
}

/*
 * findRet()
 *
 * Starting at an address somewhere after the end of a function, search for the
 * "ret" instruction that ends it. We do this by searching for a 0xc3 byte, and
 * assuming that it represents that function's "ret" instruction. This should
 * be a safe assumption. Function addresses are word-aligned, and so there's
 * usually extra space at the end of a function. This space is always padded
 * with "nop"s, so we'll end up just searching through a series of "nop"s
 * before finding our "ret". In other words, it's unlikely that we'll run into
 * a 0xc3 byte that corresponds to anything other than an actual "ret"
 * instruction.
 *
 * Note that this function only applies to x86 and x86_64, and not ARM.
 *
 * args:
 * - void* endAddr: the ending address of the function whose final "ret"
 *   instruction we want to find
 *
 * returns:
 * - an unsigned char* pointing to the address of the final "ret" instruction
 *   of the specified function
 *
 */

unsigned char *findRet(void *endAddr)
{
	unsigned char *retInstAddr = endAddr;

	while (*retInstAddr != INTEL_RET_INSTRUCTION)
		retInstAddr--;

	return retInstAddr;
}



/*
 * usage()
 *
 * Print program usage and exit.
 *
 * args:
 * - char* name: the name of the executable we're running out of
 *
 */

void usage(char *name)
{
	printf("%s [-n process-name] [-p pid] [library-to-inject]\n", name);
}
