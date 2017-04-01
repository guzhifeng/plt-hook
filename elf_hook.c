#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>
#include <linux/limits.h>
#include <stdbool.h>

#include "elf_hook.h"
#include "utils.h"
#include "ptrace.h"

static int read_header(int d, Elf_Ehdr **header)
{
	if (lseek(d, 0, SEEK_SET) < 0)
		return -errno;

	if (read(d, *header, sizeof(Elf_Ehdr)) <= 0)
		return -EINVAL;

	return 0;
}

bool is_shared_object_file(int d)
{
	Elf_Ehdr *header = NULL;
	int e_type;

	header = (Elf_Ehdr *)malloc(sizeof(Elf_Ehdr));
	if (header == NULL) {
		printf("malloc failed!\n");
		return false;
	}

	if (read_header(d, &header) < 0) {
		printf("read elf header failed!\n");
		free(header);
		return false;
	}

	e_type = header->e_type;
	free(header);

	if (e_type == ET_DYN)
		return true;
	else
		return false;
}

static int read_section_table(int d, Elf_Ehdr const *header, Elf_Shdr **table)
{
	size_t size;

	if (header == NULL || *table == NULL)
		return -EINVAL;

	size = header->e_shnum * sizeof(Elf_Shdr);

	if (lseek(d, header->e_shoff, SEEK_SET) < 0)
		return -errno;

	if (read(d, *table, size) <= 0)
		return -EINVAL;

	return 0;
}

static int read_string_table(int d, Elf_Shdr const *section,
				char const **strings)
{
	if (section == NULL || *strings == NULL)
		return -EINVAL;

	if (lseek(d, section->sh_offset, SEEK_SET) < 0)
		return -errno;

	if (read(d, (char *)*strings, section->sh_size) <= 0)
		return -EINVAL;

	return 0;
}

static int read_symbol_table(int d, Elf_Shdr const *section, Elf_Sym **table)
{
	if (section == NULL || *table == NULL)
		return -EINVAL;

	if (lseek(d, section->sh_offset, SEEK_SET) < 0)
		return -errno;

	if (read(d, *table, section->sh_size) <= 0)
		return -EINVAL;

	return 0;
}

static int read_relocation_table(int d, Elf_Shdr const *section,
					Elf_Rel **table)
{
	if (section == NULL || *table == NULL)
		return -EINVAL;

	if (lseek(d, section->sh_offset, SEEK_SET) < 0)
		return -errno;

	if (read(d, *table, section->sh_size) <= 0)
		return -EINVAL;

	return 0;
}

static int section_by_index(int d, size_t const index, Elf_Shdr **section)
{
	Elf_Ehdr *header = NULL;
	Elf_Shdr *sections = NULL;

	if (*section == NULL)
		return -EINVAL;

	header = (Elf_Ehdr *)malloc(sizeof(Elf_Ehdr));
	if (header == NULL)
		return -errno;

	if (read_header(d, &header) < 0) {
		free(header);
		return -errno;
	}

	sections = (Elf_Shdr *)malloc(header->e_shnum * sizeof(Elf_Shdr));
	if (sections == NULL) {
		free(header);
		return -errno;
	}

	if (read_section_table(d, header, &sections) < 0) {
		free(header);
		free(sections);
		return -errno;
	}

	if (index < header->e_shnum) {
		memcpy(*section, sections + index, sizeof(Elf_Shdr));
	} else {
		free(header);
		free(sections);
		return -EINVAL;
	}

	free(header);
	free(sections);

	return 0;
}

int section_by_type(int d, size_t const section_type, Elf_Shdr **section)
{
	Elf_Ehdr *header = NULL;
	Elf_Shdr *sections = NULL;
	size_t i;

	if (*section == NULL)
		return -EINVAL;

	header = (Elf_Ehdr *)malloc(sizeof(Elf_Ehdr));
	if (header == NULL)
		return -errno;

	if (read_header(d, &header) < 0) {
		free(header);
		return -errno;
	}

	sections = (Elf_Shdr *)malloc(header->e_shnum * sizeof(Elf_Shdr));
	if (sections == NULL) {
		free(header);
		return -errno;
	}

	if (read_section_table(d, header, &sections) < 0) {
		free(header);
		free(sections);
		return -errno;
	}

	for (i = 0; i < header->e_shnum; ++i) {
		if (section_type == sections[i].sh_type) {
			memcpy(*section, sections + i, sizeof(Elf_Shdr));

			break;
		}
	}

	free(header);
	free(sections);

	return 0;
}

static int section_by_name(int d, char const *section_name, Elf_Shdr **section)
{
	Elf_Ehdr *header = NULL;
	Elf_Shdr *sections = NULL;
	char const *strings = NULL;
	size_t i;

	if (*section == NULL)
		return -EINVAL;

	header = (Elf_Ehdr *)malloc(sizeof(Elf_Ehdr));
	if (header == NULL)
		return -errno;

	if (read_header(d, &header) < 0) {
		free(header);
		return -errno;
	}

	sections = (Elf_Shdr *)malloc(header->e_shnum * sizeof(Elf_Shdr));
	if (sections == NULL) {
		free(header);
		return -errno;
	}

	if (read_section_table(d, header, &sections) < 0) {
		free(header);
		free(sections);
		return -errno;
	}

	strings = (char const *)malloc((sections[header->e_shstrndx]).sh_size);
	if (strings == NULL) {
		free(header);
		free(sections);
		return -errno;
	}

	if (read_string_table(d, &sections[header->e_shstrndx], &strings) < 0) {
		free(header);
		free(sections);
		free((void *)strings);
		return -errno;
	}

	for (i = 0; i < header->e_shnum; ++i) {
		if (!strcmp(section_name, &strings[sections[i].sh_name])) {
			memcpy(*section, sections + i, sizeof(Elf_Shdr));

			break;
		}
	}

	free(header);
	free(sections);
	free((void *)strings);

	return 0;
}

int symbol_by_name(int d, Elf_Shdr *section, char const *name,
		Elf_Sym **symbol, size_t *index)
{
	Elf_Shdr *strings_section = NULL;
	char const *strings = NULL;
	Elf_Sym *symbols = NULL;
	size_t i, amount;

	*index = 0;

	if (*symbol == NULL)
		return -EINVAL;

	strings_section = (Elf_Shdr *)malloc(sizeof(Elf_Shdr));
	if (strings_section == NULL)
		return -errno;

	if (section_by_index(d, section->sh_link, &strings_section) < 0) {
		free(strings_section);
		return -errno;
	}

	strings = (char const *)malloc(strings_section->sh_size);
	if (strings == NULL) {
		free(strings_section);
		return -errno;
	}

	if (read_string_table(d, strings_section, &strings) < 0) {
		free(strings_section);
		free((void *)strings);
		return -errno;
	}

	symbols = (Elf_Sym *)malloc(section->sh_size);
	if (symbols == NULL) {
		free(strings_section);
		free((void *)strings);
		return -errno;
	}

	if (read_symbol_table(d, section, &symbols) < 0) {
		free(strings_section);
		free((void *)strings);
		free(symbols);
		return -errno;
	}

	amount = section->sh_size / sizeof(Elf_Sym);

	for (i = 0; i < amount; ++i) {
		if (!strcmp(name, &strings[symbols[i].st_name])) {
			memcpy(*symbol, symbols + i, sizeof(Elf_Sym));
			*index = i;

			break;
		}
	}

	free(strings_section);
	free((void *)strings);
	free(symbols);

	return 0;
}

int elf_hook(pid_t target, char *funcname, char *new_libname,
		char *orig_libname)
{
	static size_t pagesize;
	int desc;
	char *tgt_elfpath;

	errno = 0;

	/* ".dynsym" section header */
	Elf_Shdr *dynsym = NULL;

	/* ".rel.plt" section header */
	Elf_Shdr *rel_plt = NULL;

	/* symbol table entry for symbol named "name" */
	Elf_Sym *symbol = NULL;

	/* array with ".rel.plt" entries */
	Elf_Rel *rel_plt_table = NULL;
	Elf_Rel *relplt_t = NULL;

	size_t
	i,
	name_index,  //index of symbol named "name" in ".dyn.sym"
	rel_plt_amount;  // amount of ".rel.plt" entries

	/* address of relocation for symbol named "name" */
	void *module_address = NULL;
	void *name_address;

	/* address of the symbol being substituted */
	long *original = NULL;
	long *subst = NULL;

	tgt_elfpath = malloc(PATH_MAX * sizeof(char));
	if (tgt_elfpath == NULL) {
		printf("malloc failed!\n");
		return -1;
	}

	if (get_proc_elfpath(target, &tgt_elfpath) < 0)
		goto hook_err1;

	subst = calloc(1, sizeof(long));
	if (subst == NULL)
		goto hook_err1;

	*subst = get_tgt_funcaddr(target, funcname, new_libname);
	if (*subst < 0)
		goto hook_err2;

	if (!pagesize)
		pagesize = sysconf(_SC_PAGESIZE);

	desc = open(tgt_elfpath, O_RDONLY);
	if (desc < 0)
		goto hook_err2;

	/* get ".dynsym" section */
	dynsym = (Elf_Shdr *)malloc(sizeof(Elf_Shdr));
	if (dynsym == NULL)
		goto hook_err3;

	if (section_by_type(desc, SHT_DYNSYM, &dynsym) < 0)
		goto hook_err4;

	/* only need the index of symbol named "name" in the ".dynsym" table */
	symbol = (Elf_Sym *)malloc(sizeof(Elf_Sym));
	if (symbol == NULL)
		goto hook_err4;

	if (symbol_by_name(desc, dynsym, funcname, &symbol, &name_index) < 0)
		goto hook_err5;

	/* get ".rel.plt" (for 32-bit) or ".rela.plt" (for 64-bit) section */
	rel_plt = (Elf_Shdr *)malloc(sizeof(Elf_Shdr));
	if (rel_plt == NULL)
		goto hook_err5;

	if (section_by_name(desc, REL_PLT, &rel_plt) < 0)
		goto hook_err6;

	if (is_shared_object_file(desc))
		module_address = (void *)get_base_addr(target, tgt_elfpath, NULL);
	/* get ".rel.dyn" (for 32-bit) or ".rela.dyn" (for 64-bit) section */
	/* init the ".rel.plt" array and get its size */
	rel_plt_table = (Elf_Rel *)((size_t)module_address + rel_plt->sh_addr);
	rel_plt_amount = rel_plt->sh_size / sizeof(Elf_Rel);

	/* now we've got ".rel.plt" (needed for PIC) table
	 * and ".rel.dyn" (for non-PIC) table
	 * and the symbol's index
	 * lookup the ".rel.plt" table
	 */
	relplt_t = calloc(1, sizeof(Elf_Rel));
	if (relplt_t == NULL)
		goto hook_err6;

	original = calloc(1, sizeof(long));
	if (original == NULL)
		goto hook_err7;

	for (i = 0; i < rel_plt_amount; ++i) {
		if (ptrace_read(target, (unsigned long)&(rel_plt_table[i]),
					(void *)relplt_t, sizeof(Elf_Rel)) < 0)
			goto hook_err8;
		/* if we found the symbol to substitute in ".rel.plt" */
		if (ELF_R_SYM(relplt_t->r_info) == name_index) {
			/* the target symbol appears in ".rel.plt" only once */
			break;
		}
	}

	name_address = (void *)(module_address + relplt_t->r_offset);
	/*save the original function address, and replace it
	 * with the substitutional
	 */
	if (ptrace_read(target, (unsigned long)name_address,
				original, sizeof(long)) < 0)
		goto hook_err8;
	ptrace_write(target, (unsigned long)name_address, subst, sizeof(long));

hook_err8:
	free(original);
hook_err7:
	free(relplt_t);
hook_err6:
	free(rel_plt);
hook_err5:
	free(symbol);
hook_err4:
	free(dynsym);
hook_err3:
	close(desc);
hook_err2:
	free(subst);
hook_err1:
	free(tgt_elfpath);
	return -errno;
}

int parse_symbol_list(pid_t target, struct list_head *list,
		char *orig_libname)
{
	int tgt_desc;
	int origlib_desc;
	char *tgt_elfpath;
	char *orig_libpath;

	errno = 0;

	/* original library's ".dynsym" section header */
	Elf_Shdr *origlib_dynsym = NULL;

	/* taget process's ".rel.plt" section header */
	Elf_Shdr *tgt_relplt = NULL;
	Elf_Rel *tgt_relplt_t = NULL;

	size_t i, j;
	size_t n_origlib_dynsym, n_tgt_relplt;

	Elf_Shdr *tgt_symsect = NULL;
	Elf_Shdr *tgt_strsect = NULL;
	Elf_Sym *tgt_syms = NULL;
	char const *tgt_strs = NULL;

	Elf_Shdr *origlib_strsect = NULL;
	char const *origlib_strs = NULL;
	Elf_Sym *origlib_syms = NULL;
	struct symstr_list *tmp;

	orig_libpath = (char *)calloc(1, PATH_MAX * sizeof(char));
	if (orig_libpath == NULL)
		return -errno;

	if (get_libpath(target, orig_libname, &orig_libpath) < 0) {
		free(orig_libpath);
		return -1;
	}

	origlib_desc = open(orig_libpath, O_RDONLY);
	if (origlib_desc < 0) {
		free(orig_libpath);
		return -errno;
	}

	free(orig_libpath);

	origlib_dynsym = (Elf_Shdr *)malloc(sizeof(Elf_Shdr));
	if (origlib_dynsym == NULL)
		goto err1;

	/* get orignal library's ".dynsym" section */
	if (section_by_type(origlib_desc, SHT_DYNSYM, &origlib_dynsym) < 0)
		goto err2;

	origlib_strsect = (Elf_Shdr *)malloc(sizeof(Elf_Shdr));
	if (origlib_strsect == NULL)
		goto err2;

	if (section_by_index(origlib_desc, origlib_dynsym->sh_link,
				&origlib_strsect) < 0)
		goto err3;

	origlib_strs = (char const *)malloc(origlib_strsect->sh_size);
	if (origlib_strs == NULL)
		goto err3;

	if (read_string_table(origlib_desc, origlib_strsect, &origlib_strs) < 0)
		goto err4;

	origlib_syms = (Elf_Sym *)malloc(origlib_dynsym->sh_size);
	if (origlib_syms == NULL)
		goto err4;

	if (read_symbol_table(origlib_desc, origlib_dynsym, &origlib_syms) < 0)
		goto err5;

	tgt_elfpath = malloc(PATH_MAX * sizeof(char));
	if (tgt_elfpath == NULL)
		goto err5;

	if (get_proc_elfpath(target, &tgt_elfpath) < 0)
		goto err6;

	tgt_desc = open(tgt_elfpath, O_RDONLY);
	if (tgt_desc < 0)
		goto err6;

	/* get target's ".rela.plt" (for 64-bit) section */
	tgt_relplt = (Elf_Shdr *)malloc(sizeof(Elf_Shdr));
	if (tgt_relplt == NULL)
		goto err7;

	if (section_by_name(tgt_desc, REL_PLT, &tgt_relplt) < 0)
		goto err8;

	tgt_symsect = (Elf_Shdr *)malloc(sizeof(Elf_Shdr));
	if (tgt_symsect == NULL)
		goto err8;

	if (section_by_index(tgt_desc, tgt_relplt->sh_link, &tgt_symsect) < 0)
		goto err9;

	tgt_strsect = (Elf_Shdr *)malloc(sizeof(Elf_Shdr));
	if (tgt_strsect == NULL)
		goto err9;

	if (section_by_index(tgt_desc, tgt_symsect->sh_link, &tgt_strsect) < 0)
		goto err10;

	tgt_relplt_t = (Elf_Rel *)malloc(tgt_relplt->sh_size);
	if(tgt_relplt_t == NULL)
		goto err10;

	if (read_relocation_table(tgt_desc, tgt_relplt, &tgt_relplt_t) < 0)
		goto err11;

	tgt_syms = (Elf_Sym *)malloc(tgt_symsect->sh_size);
	if (tgt_syms == NULL)
		goto err11;

	if (read_symbol_table(tgt_desc, tgt_symsect, &tgt_syms) < 0)
		goto err12;

	tgt_strs = (char const *)malloc(tgt_strsect->sh_size);
	if (tgt_strs == NULL)
		goto err12;

	if (read_string_table(tgt_desc, tgt_strsect, &tgt_strs))
		goto err13;

	n_origlib_dynsym = origlib_dynsym->sh_size / origlib_dynsym->sh_entsize;
	n_tgt_relplt = tgt_relplt->sh_size / tgt_relplt->sh_entsize;

	for (i = 0; i < n_tgt_relplt; ++i) {
		long index = (tgt_syms + ELF64_R_SYM(tgt_relplt_t[i].r_info))->st_name;
		for (j = 0; j < n_origlib_dynsym; ++j) {
			if (!strcmp(&tgt_strs[index], &origlib_strs[origlib_syms[j].st_name])
					&& origlib_syms[j].st_size) {
				tmp = (struct symstr_list *)malloc(sizeof(struct symstr_list));
				tmp->string = (char *)malloc(strlen(&tgt_strs[index]) + 1);
				memcpy(tmp->string, &tgt_strs[index], strlen(&tgt_strs[index]) + 1);
				list_add_tail(&(tmp->list), list);
			}
		}
	}

err13:
	free((void *)tgt_strs);
err12:
	free(tgt_syms);
err11:
	free(tgt_relplt_t);
err10:
	free(tgt_strsect);
err9:
	free(tgt_symsect);
err8:
	free(tgt_relplt);
err7:
	close(tgt_desc);
err6:
	free(tgt_elfpath);
err5:
	free(origlib_syms);
err4:
	free((void *)origlib_strs);
err3:
	free(origlib_strsect);
err2:
	free(origlib_dynsym);
err1:
	close(origlib_desc);

	return -errno;
}
