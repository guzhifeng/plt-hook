#pragma once
#include <elf.h>
/*
 * rename standart types for convenience
 */
#ifdef __x86_64
    #define Elf_Ehdr Elf64_Ehdr
    #define Elf_Shdr Elf64_Shdr
    #define Elf_Sym Elf64_Sym
    #define Elf_Rel Elf64_Rela
    #define ELF_R_SYM ELF64_R_SYM
    #define REL_DYN ".rela.dyn"
    #define REL_PLT ".rela.plt"
#else
    #define Elf_Ehdr Elf32_Ehdr
    #define Elf_Shdr Elf32_Shdr
    #define Elf_Sym Elf32_Sym
    #define Elf_Rel Elf32_Rel
    #define ELF_R_SYM ELF32_R_SYM
    #define REL_DYN ".rel.dyn"
    #define REL_PLT ".rel.plt"
#endif


int section_by_type(int d, size_t const section_type, Elf_Shdr **section);

int symbol_by_name(int d, Elf_Shdr *section, char const *name, Elf_Sym **symbol, size_t *index);

//int get_module_base_address(char const *module_filename, void *handle, void **base);
void *elf_hook(pid_t target, char *funcname, char *newLibName, char *origLibName);
