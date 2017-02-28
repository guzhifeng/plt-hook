#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <errno.h>

#include "elf_hook.h"

static int read_header(int d, Elf_Ehdr **header)
{
	*header = (Elf_Ehdr *)malloc(sizeof(Elf_Ehdr));
	if (*header == NULL)
		return errno;

	if (lseek(d, 0, SEEK_SET) < 0) {
		free(*header);
		return errno;
	}

	if (read(d, *header, sizeof(Elf_Ehdr)) <= 0) {
		free(*header);
		return errno = EINVAL;
	}

	return 0;
}

static int read_section_table(int d, Elf_Ehdr const *header, Elf_Shdr **table)
{
	size_t size;

	if (header == NULL)
		return errno = EINVAL;

	size = header->e_shnum * sizeof(Elf_Shdr);
	*table = (Elf_Shdr *)malloc(size);
	if (*table == NULL)
		return errno;

	if (lseek(d, header->e_shoff, SEEK_SET) < 0) {
		free(*table);
		return errno;
	}

	if (read(d, *table, size) <= 0) {
		free(*table);
		return errno = EINVAL;
	}

	return 0;
}

static int read_string_table(int d, Elf_Shdr const *section,
				char const **strings)
{
	if (section == NULL)
		return errno = EINVAL;

	*strings = (char const *)malloc(section->sh_size);
	if (*strings == NULL)
		return errno;

	if (lseek(d, section->sh_offset, SEEK_SET) < 0) {
		free((void *)*strings);
		return errno;
	}

	if (read(d, (char *)*strings, section->sh_size) <= 0) {
		free((void *)*strings);
		return errno = EINVAL;
	}

	return 0;
}

static int read_symbol_table(int d, Elf_Shdr const *section, Elf_Sym **table)
{
	if (section == NULL)
		return errno = EINVAL;

	*table = (Elf_Sym *)malloc(section->sh_size);
	if (*table == NULL)
		return errno;

	if (lseek(d, section->sh_offset, SEEK_SET) < 0) {
		free(*table);
		return errno;
	}

	if (read(d, *table, section->sh_size) <= 0) {
		free(*table);
		return errno = EINVAL;
	}

	return 0;
}
/*
static int read_relocation_table(int d, Elf_Shdr const *section,
					Elf_Rel **table)
{
	if (section == NULL)
		return EINVAL;

	*table = (Elf_Rel *)malloc(section->sh_size);
	if(*table == NULL)
	    return errno;

	if (lseek(d, section->sh_offset, SEEK_SET) < 0) {
	    free(*table);
	    return errno;
	}

	if (read(d, *table, section->sh_size) <= 0) {
	    free(*table);
	    return errno = EINVAL;
	}

	return 0;
}
*/

static int section_by_index(int d, size_t const index, Elf_Shdr **section)
{
	Elf_Ehdr *header = NULL;
	Elf_Shdr *sections = NULL;

	*section = NULL;

	if (read_header(d, &header) || read_section_table(d, header, &sections))
		return errno;

	if (index < header->e_shnum) {
		*section = (Elf_Shdr *)malloc(sizeof(Elf_Shdr));

		if (*section == NULL) {
			free(header);
			free(sections);

			return errno;
		}

		 memcpy(*section, sections + index, sizeof(Elf_Shdr));
	} else {
		return errno = EINVAL;
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

	*section = NULL;

	if (read_header(d, &header) || read_section_table(d, header, &sections))
		return errno;

	for (i = 0; i < header->e_shnum; ++i) {
		if (section_type == sections[i].sh_type) {
			*section = (Elf_Shdr *)malloc(sizeof(Elf_Shdr));
			if (*section == NULL) {
				free(header);
				free(sections);

				return errno;
			}

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

	*section = NULL;

	if (read_header(d, &header)
	|| read_section_table(d, header, &sections)
	|| read_string_table(d, &sections[header->e_shstrndx], &strings))
		return errno;

	for (i = 0; i < header->e_shnum; ++i) {
		if (!strcmp(section_name, &strings[sections[i].sh_name])) {
			*section = (Elf_Shdr *)malloc(sizeof(Elf_Shdr));

			if (*section == NULL) {
				free(header);
				free(sections);
				free((void *)strings);

				return errno;
			}

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

	*symbol = NULL;
	*index = 0;

	if (section_by_index(d, section->sh_link, &strings_section) ||
	    read_string_table(d, strings_section, &strings) ||
	    read_symbol_table(d, section, &symbols))
		return errno;

	amount = section->sh_size / sizeof(Elf_Sym);

	for (i = 0; i < amount; ++i) {
		if (!strcmp(name, &strings[symbols[i].st_name])) {
			*symbol = (Elf_Sym *)malloc(sizeof(Elf_Sym));

			if (*symbol == NULL) {
				free(strings_section);
				free((void *)strings);
				free(symbols);

				return errno;
			}

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

/*
int get_module_base_address(char const *elf_name,
			void *handle, void **base)
{
	int descriptor;
	Elf_Shdr *dynsym = NULL, *strings_section = NULL;
	char const *strings = NULL;
	Elf_Sym *symbols = NULL;
	size_t i, amount;
	Elf_Sym *found = NULL;

	*base = NULL;

	descriptor = open(elf_name, O_RDONLY);

	if (descriptor < 0)
		return errno;

	// get ".dynsym" section
	if (section_by_type(descriptor, SHT_DYNSYM, &dynsym)
	    section_by_index(descriptor, dynsym->sh_link, &strings_section) ||
	    read_string_table(descriptor, strings_section, &strings) ||
	    read_symbol_table(descriptor, dynsym, &symbols)) {
		free(strings_section);
		free((void *)strings);
		free(symbols);
		free(dynsym);
		close(descriptor);

		return errno;
	}

	amount = dynsym->sh_size / sizeof(Elf_Sym);

	// Trick to get the module base address in a portable way:
	// Find the first GLOBAL or WEAK symbol in the symbol table,
	// look this up with dlsym, then return the difference
	// as the base address

	for (i = 0; i < amount; ++i) {
		switch (ELF32_ST_BIND(symbols[i].st_info)) {
			case STB_GLOBAL:
			case STB_WEAK:
				found = &symbols[i];
				break;
			default:
				break;
	    }
	}

	if (found != NULL) {
		const char *name = &strings[found->st_name];
		void *sym = dlsym(handle, name);
		if(sym != NULL)
			*base = (void*)((size_t)sym - found->st_value);
	}

	free(strings_section);
	free((void *)strings);
	free(symbols);
	free(dynsym);
	close(descriptor);

	return *base == NULL;
}
*/

void *elf_hook(char const *elf_name, char const *name,
		void const *substitution)
{
	static size_t pagesize;
	int descriptor;

	Elf_Shdr
	*dynsym = NULL,  // ".dynsym" section header
	*rel_plt = NULL,  // ".rel.plt" section header
	*rel_dyn = NULL;  // ".rel.dyn" section header

	Elf_Sym
	*symbol = NULL;  //symbol table entry for symbol named "name"

	Elf_Rel
	*rel_plt_table = NULL,  //array with ".rel.plt" entries
	*rel_dyn_table = NULL;  //array with ".rel.dyn" entries

	size_t
	i,
	name_index,  //index of symbol named "name" in ".dyn.sym"
	rel_plt_amount,  // amount of ".rel.plt" entries
	rel_dyn_amount,  // amount of ".rel.dyn" entries
	*name_address = NULL;  //address of relocation for symbol named "name"

	/* address of the symbol being substituted */
	void *original = NULL;

	if (name == NULL || substitution == NULL)
		return original;

	if (!pagesize)
		pagesize = sysconf(_SC_PAGESIZE);

	descriptor = open(elf_name, O_RDONLY);

	if (descriptor < 0)
		return original;

 	/* get ".dynsym" section */
	if (section_by_type(descriptor, SHT_DYNSYM, &dynsym) ||
	/* only need the index of symbol named "name" in the ".dynsym" table */
	symbol_by_name(descriptor, dynsym, name, &symbol, &name_index) ||
	/* get ".rel.plt" (for 32-bit) or ".rela.plt" (for 64-bit) section */
	section_by_name(descriptor, REL_PLT, &rel_plt) ||
	/* get ".rel.dyn" (for 32-bit) or ".rela.dyn" (for 64-bit) section */
	section_by_name(descriptor, REL_DYN, &rel_dyn)) {
		/* if something went wrong */
		free(dynsym);
		free(rel_plt);
		free(rel_dyn);
		free(symbol);
		close(descriptor);

		return original;
	}

	free(dynsym);
	free(symbol);

	/* init the ".rel.plt" array and get its size */
	rel_plt_table = (Elf_Rel *)(rel_plt->sh_addr);
	rel_plt_amount = rel_plt->sh_size / sizeof(Elf_Rel);

	/* init the ".rel.dyn" array and get its size */
	rel_dyn_table = (Elf_Rel *)(rel_dyn->sh_addr);
	rel_dyn_amount = rel_dyn->sh_size / sizeof(Elf_Rel);

	free(rel_plt);
	free(rel_dyn);
	close(descriptor);

	/* now we've got ".rel.plt" (needed for PIC) table 
	 * and ".rel.dyn" (for non-PIC) table 
	 * and the symbol's index
	 * lookup the ".rel.plt" table
	 */
	for (i = 0; i < rel_plt_amount; ++i) {
		/* if we found the symbol to substitute in ".rel.plt" */
		if (ELF_R_SYM(rel_plt_table[i].r_info) == name_index) {
			name_address = (size_t *)(rel_plt_table[i].r_offset);
			/*save the original function address, and replace it
			 * with the substitutional
			 */
			original =
				(void *)*(size_t *)(rel_plt_table[i].r_offset);
			/* mark a memory page contains relocation as writable */
			if (mprotect((void *)(((size_t)name_address) &
				(((size_t)-1) ^ (pagesize - 1))),
				pagesize, PROT_READ | PROT_WRITE) < 0)
				return NULL;

			*(size_t *)(rel_plt_table[i].r_offset) =
				(size_t)substitution;

			/* mark a memory page contains relocation as executable */
			if (mprotect((void *)(((size_t)name_address) &
				(((size_t)-1) ^ (pagesize - 1))), pagesize,
						PROT_READ | PROT_EXEC) < 0)
				return NULL;

			/* the target symbol appears in ".rel.plt" only once */
			break;
		}
	}

	if (original)
		return original;

	/* we will get here only with 32-bit non-PIC module look up 
	 * the ".rel.dyn" table
	 */
	for (i = 0; i < rel_dyn_amount; ++i)
		/* if we found the symbol to substitute in ".rel.dyn" */
		if (ELF_R_SYM(rel_dyn_table[i].r_info) == name_index) {
			/* get the relocation address (address of a relative
			 * CALL (0xE8) instruction's argument)
			 */
			name_address = (size_t *)(rel_dyn_table[i].r_offset);

			/* calculate an address of the original function by
			 * a relative CALL (0xE8) instruction's argument
			 */
			if (!original)
				original = (void *)(*name_address +
					(size_t)name_address + sizeof(size_t));

			/* mark page contains the relocation as writable */
			if (mprotect((void *)(((size_t)name_address) &
				(((size_t)-1) ^ (pagesize - 1))), pagesize,
					PROT_READ | PROT_WRITE) < 0) {
				return NULL;
		}

		/* calculate a new relative CALL (0xE8)instruction's argument
		 * for the substitutional function and write it down
		 */
		*name_address = (size_t)substitution -
			(size_t)name_address - sizeof(size_t);

		/* mark page that contains the relocation back as executable */
		if (mprotect((void *)(((size_t)name_address) & (((size_t)-1) ^
		(pagesize - 1))), pagesize, PROT_READ | PROT_EXEC) < 0) {
			/* something wrong, so restore original. */
			*name_address = (size_t)original - (size_t)name_address
				- sizeof(size_t);
			return NULL;
		}
	}

	return original;
}
