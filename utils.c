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

static void inject_target_snippet(pid_t target, long addr, char *backup, size_t code_len)
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
	target_snippet_ret = (intptr_t)find_ret_inst(target_snippet_end) -
		(intptr_t)target_snippet;

	/* back up whatever data at the address we want to modify. */
	ptrace_read(target, addr, backup, code_len);

	/* set up a buffer and copy target_snippet() code into the
	 * target process.
	 */
	newcode = calloc(1, code_len * sizeof(char));
	memcpy(newcode, target_snippet, code_len - 1);
	/* overwrite the RET instruction with an INT 3. */
	newcode[target_snippet_ret] = INTEL_INT3_INSTRUCTION;

	/* copy target_snippet()'s code to the target address inside the
	 * target process' address space.
	 */
	ptrace_write(target, addr, newcode, code_len);
	free(newcode);
}

/*
 * get_libc_funcaddr()
 *
 * Find the address of a function within our own loaded copy of libc.so.
 *
 * args:
 * - char* funcname: name of the function whose address we want to find
 *
 * returns:
 * - a long containing the address of that function
 *
 */
static long get_libc_funcaddr(char *funcname)
{
	void *self;
	long func_addr;

	self = dlopen("libc.so.6", RTLD_LAZY);
	func_addr = (long)dlsym(self, funcname);

	return func_addr;
}

/*
 * get_base_addr()
 *
 * Gets the base address of memory inside a process by reading /proc/pid/maps.
 *
 * args:
 * - pid_t pid: pid of the process whose base address we'd like to find
 * - char *libstr : subset string of the string name
 *
 * returns:
 * - a long containing the base address inside that process
 *
 */
long get_base_addr(pid_t pid, char *libstr, long *len)
{
	FILE *fp;
	char filename[30];
	char line[850];
	long start;
	long end;

	sprintf(filename, "/proc/%d/maps", pid);

	fp = fopen(filename, "r");
	if (fp == NULL)
		return -1;

	while (fgets(line, 850, fp) != NULL) {
		sscanf(line, "%lx-%lx %*s %*s %*s %*d %*s", &start, &end);
		if (strstr(line, libstr) != NULL)
			break;
	}

	if (len != NULL)
		*len = end - start;

	fclose(fp);
	return start;
}

/*
 * get_freespace_addr()
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
static long get_freespace_addr(pid_t pid)
{
	FILE *fp;
	char filename[PATH_MAX];
	char line[PATH_MAX];
	long addr;
	char str[20];
	char perms[5];

	sprintf(filename, "/proc/%d/maps", pid);

	fp = fopen(filename, "r");
	if (fp == NULL)
		return -1;

	while (fgets(line, 850, fp) != NULL) {
		sscanf(line, "%lx-%*lx %s %*s %s %*d", &addr, perms, str);
		if (strstr(perms, "x") != NULL)
			break;
	}

	fclose(fp);
	return addr;
}

/*
 * check_loaded()
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
static int check_loaded(pid_t pid, char *libname)
{
	FILE *fp;
	char filename[30], line[850];
	long addr;

	sprintf(filename, "/proc/%d/maps", pid);

	fp = fopen(filename, "r");
	if (fp == NULL)
		return -1;

	while (fgets(line, 850, fp) != NULL) {
		sscanf(line, "%lx-%*lx %*s %*s %*s %*d", &addr);
		if (strstr(line, libname) != NULL) {
			fclose(fp);
			return 1;
		}
	}

	fclose(fp);
	return -1;
}

size_t inject_shared_library(pid_t target, char *new_libname, char *orig_libname)
{
	char *libpath;
	int libpath_len;
	char filename[30];
	FILE *fp;
	char line[PATH_MAX];
	long start, end;
	pid_t mypid = 0;
	long my_libcaddr, tgt_libcaddr;
	long my_mallocaddr, my_freeaddr;
	long my_dlopenaddr, my_munmapaddr;
	long malloc_offset, free_offset;
	long dlopen_offset, munmap_offset;
	long tgt_mallocaddr, tgt_freeaddr;
	long tgt_dlopenaddr, tgt_munmapaddr;
	struct user_regs_struct oldregs, regs;
	struct user_regs_struct target_regs;
	long addr, curr;
	size_t target_snippet_size;
	unsigned long long tgt_buf;
	unsigned long long lib_addr;
	char *backup;
	int error = 0;

	libpath = realpath(new_libname, NULL);
	if (!libpath) {
		printf("can't find file \"%s\"\n", new_libname);
		return -1;
	}

	libpath_len = strlen(libpath) + 1;

	mypid = getpid();

	my_libcaddr = get_base_addr(mypid, "libc-", NULL);
	if (!my_libcaddr)
		return -1;

	tgt_libcaddr = get_base_addr(target, "libc-", NULL);
	if (!tgt_libcaddr)
		return -1;

	/* find the addresses of the syscalls that we'd like to use inside the
	 * target, use the base address of libc of THIS process to calculate
	 * offsets for the syscalls
	 */
	my_mallocaddr = get_libc_funcaddr("malloc");
	my_freeaddr = get_libc_funcaddr("free");
	my_dlopenaddr = get_libc_funcaddr("__libc_dlopen_mode");
	my_munmapaddr = get_libc_funcaddr("munmap");

	malloc_offset = my_mallocaddr - my_libcaddr;
	free_offset = my_freeaddr - my_libcaddr;
	dlopen_offset = my_dlopenaddr - my_libcaddr;
	munmap_offset = my_munmapaddr - my_libcaddr;

	/* get the target process' libc function address */
	tgt_mallocaddr = tgt_libcaddr + malloc_offset;
	tgt_freeaddr = tgt_libcaddr + free_offset;
	tgt_dlopenaddr = tgt_libcaddr + dlopen_offset;
	tgt_munmapaddr = tgt_libcaddr + munmap_offset;

	memset(&oldregs, 0, sizeof(struct user_regs_struct));
	memset(&regs, 0, sizeof(struct user_regs_struct));

	//ptrace_attach(target);
	ptrace_getregs(target, &oldregs);
	memcpy(&regs, &oldregs, sizeof(struct user_regs_struct));

	/* find a good address and copy target_snippet() to it */
	addr = get_freespace_addr(target);
	if (!addr)
		return -1;

	addr += sizeof(long);

	target_snippet_size = (intptr_t)target_snippet_end -
		(intptr_t)target_snippet;
	backup = calloc(1, target_snippet_size * sizeof(char));
	if (backup == NULL) {
		return -errno;
	}

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
	regs.r9 = tgt_mallocaddr;
	regs.rdi = libpath_len;
	ptrace_setregs(target, &regs);

	/* call malloc() */
	ptrace_cont(target);

	/* the target process malloc() returns. check wether it succeeded */
	memset(&target_regs, 0, sizeof(struct user_regs_struct));
	ptrace_getregs(target, &target_regs);
	tgt_buf = target_regs.rax;
	if (tgt_buf == 0) {
		error = -1;
		printf("malloc() failed to allocate memory\n");
		goto inject_error;
	}

	/* malloc() succeeded, copy path of shared lib into the malloc'd
	 * buffer.
	 */
	ptrace_write(target, tgt_buf, libpath, libpath_len);

	/* continue the target's execution and call __libc_dlopen_mode. */
	regs.rip = addr + 2;
	regs.r9 = tgt_dlopenaddr;
	regs.rdi = tgt_buf;
	regs.rsi = RTLD_NOW;

	ptrace_setregs(target, &regs);
	ptrace_cont(target);

	memset(&target_regs, 0, sizeof(struct user_regs_struct));
	ptrace_getregs(target, &target_regs);
	lib_addr = target_regs.rax;

	/* if rax is 0 here, dlopen() failed, bail out cleanly. */
	if (lib_addr == 0) {
		error = -1;
		fprintf(stderr, "dlopen() failed to load %s\n", new_libname);
		goto inject_error;
	}

	/* now check /proc/pid/maps to see whether injection succecced. */
	if (check_loaded(target, new_libname))
		printf("\"%s\" successfully injected\n", new_libname);
	else {
		error = -1;
		fprintf(stderr, "could not inject \"%s\"\n", new_libname);
		goto inject_error;
	}

	/* call free() and we don't care whether this succeeds, so don't
	 * bother checking the return value.
	 */
	regs.rip = addr + 2;
	regs.r9 = tgt_freeaddr;
	regs.rdi = tgt_buf;
	ptrace_setregs(target, &regs);
	ptrace_cont(target);


	/* call munmap() to free orignal library memory. */
	sprintf(filename, "/proc/%d/maps", target);
	fp = fopen(filename, "r");
	if (fp == NULL)
		return -1;

	while (fgets(line, 850, fp) != NULL) {
		sscanf(line, "%lx-%lx %*s %*s %*s %*d %*s", &start, &end);
		if (strstr(line, orig_libname) != NULL) {
			regs.rip = addr + 2;
			regs.r9 = tgt_munmapaddr;
			regs.rdi = start;
			regs.rsi = end - start;
			ptrace_setregs(target, &regs);
			ptrace_cont(target);
			memset(&target_regs, 0, sizeof(struct user_regs_struct));
			ptrace_getregs(target, &target_regs);
			if (target_regs.rax < 0) {
				printf("free origlib memory failed\n");
				return -1;
			}
		}
	}

	ptrace_write(target, addr, backup, target_snippet_size);
	ptrace_setregs(target, &oldregs);
	free(backup);
	return error;

inject_error:
	/* restore the old state and detach from the target. */
	restoreStateAndDetach(target, addr, backup,
			target_snippet_size, oldregs);
	free(backup);
	return error;
}

/*
 * check_stack()
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
int check_stack(pid_t pid, long addr, char* libname)
{
	long func_addr, func_size;
	char *libpath;
	long libaddr;
	int desc;
	long liblen;

	libpath = (char *)calloc(1, PATH_MAX * sizeof(char));
	if (get_libpath(pid, libname, &libpath) < 0) {
		return -1;
	}

	libaddr = get_base_addr(pid, libname, &liblen);
	desc = open(libpath, O_RDONLY);
	if (desc < 0) {
		fprintf(stderr, "can't open \"%s\"\n", libpath);
		free(libpath);
		return -1;
	}

	if ((addr >= libaddr) && (addr <= libaddr + liblen)) {
		printf("stack safety check failed for \"%d\"\n", pid);
		return -1;
	}

	free(libpath);
	close(desc);
	return 0;
}

long get_tgt_funcaddr(pid_t target, char* funcname, char* libname)
{
	long func_addr;
	char *libpath;
	long libaddr;
	int desc;
	size_t name_index;

	/* read function length in .dynsym */
	Elf_Shdr *dynsym = NULL;
	Elf_Sym *symbol = NULL;

	libpath = (char *)calloc(1, PATH_MAX * sizeof(char));
	if (libpath == NULL)
		return -1;

	if (get_libpath(target, libname, &libpath) < 0) {
		free(libpath);
		return -1;
	}

	libaddr = get_base_addr(target, libname, NULL);
	if (libaddr < 0) {
		free(libpath);
		return -1;
	}

	desc = open(libpath, O_RDONLY);
	if (desc < 0) {
		free(libpath);
		printf("can't open %s\n", libpath);
		return -1;
	}

	/* get symbol named "funcname" in the ".dynsym" section */
	dynsym = (Elf_Shdr *)malloc(sizeof(Elf_Shdr));
	if (dynsym == NULL) {
		close(desc);
		free(libpath);
		return -errno;
	}

	if (section_by_type(desc, SHT_DYNSYM, &dynsym) < 0) {
		free(dynsym);
		close(desc);
		free(libpath);
		return -errno;
	}

	symbol = (Elf_Sym *)malloc(sizeof(Elf_Sym));
	if (symbol == NULL) {
		free(dynsym);
		close(desc);
		free(libpath);
		return -errno;
	}

	if (symbol_by_name(desc, dynsym, funcname, &symbol, &name_index)) {
		free(dynsym);
		close(desc);
		free(libpath);
		free(symbol);
		return -errno;
	}

	func_addr = libaddr + symbol->st_value;

	free(dynsym);
	close(desc);
	free(libpath);
	free(symbol);

	return func_addr;
}

/*
 * find_proc_by_name()
 *
 * Given the name of a process, try to find its PID by searching through /proc
 * and reading /proc/[pid]/exe until we find a process whose name matches the
 * given process.
 *
 * args:
 * - char* procname: name of the process whose pid to find
 *
 * returns:
 * - a pid_t containing the pid of the process (or -1 if not found)
 *
 */

pid_t find_proc_by_name(char *procname)
{
	DIR *directory;
	struct dirent *procDirs;
	int exePathLen;
	char *exePath, *exeBuf;
	ssize_t len;
	char *exeName, *exeToken;

	if (procname == NULL)
		return -1;

	directory = opendir("/proc/");
	if (directory == NULL) {
		printf("opendir() failed!\n");
		return -1;
	}

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

		if (strcmp(exeName, procname) == 0) {
			free(exePath);
			free(exeBuf);
			closedir(directory);
			return pid;
		}

		free(exePath);
		free(exeBuf);
	}

	closedir(directory);
	return -1;
}

/*
 * get_proc_elfpath()
 *
 * Gets the name of original lib by readlink of /proc/pid/exe.
 *
 * args:
 * - pid_t pid: pid of the process we'd like to find
 * - char *elfPath:
 *
 * returns:
 * - success 0; fail -1
 *
 */

int get_proc_elfpath(pid_t pid, char **elfpath)
{
	FILE *fp;
	char exename[30];
	char line[850];
	int len;

	if (*elfpath == NULL)
		return -1;

	sprintf(exename, "/proc/%d/exe", pid);

	len = readlink(exename, *elfpath, PATH_MAX - 1);
	if (len == -1) {
		printf("readlink failed %d!\n", errno);
		return -1;
	}

	(*elfpath)[len] = '\0';
	return 0;
}

/*
 * get_libpath()
 *
 * Gets the name of lib by reading /proc/pid/maps.
 *
 * args:
 * - pid_t pid: pid of the process we'd like to find
 * - char *libstr: sub-string of libname
 *
 * returns:
 * - a long containing the base address of libc.so inside that process
 *
 */

int get_libpath(pid_t pid, char *libstr, char **libpath)
{
	FILE *fp;
	char filename[30];
	char line[850];
	int len;

	sprintf(filename, "/proc/%d/maps", pid);

	fp = fopen(filename, "r");
	if (fp == NULL)
		return -1;

	while (fgets(line, 850, fp) != NULL) {
		sscanf(line, "%*lx-%*lx %*s %*s %*s %*d %s", *libpath);
		if (strstr(line, libstr) != NULL) {
			len = strlen(*libpath);
			(*libpath)[len] = '\0';

			fclose(fp);
			return 0;
		}
	}

	printf("can not find the filepath of %s\n", libstr);
	fclose(fp);
	return -1;
}


/*
 * find_ret_inst()
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

unsigned char *find_ret_inst(void *endaddr)
{
	unsigned char *ret_instaddr = endaddr;

	while (*ret_instaddr != INTEL_RET_INSTRUCTION)
		ret_instaddr--;

	return ret_instaddr;
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
	printf("%s [-n process-name] [-p pid] [original-library] [library-to-inject]\n", name);
}
