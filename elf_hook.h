#pragma once

#ifdef __cplusplus
extern "C"
{
#endif

//int get_module_base_address(char const *module_filename, void *handle, void **base);
void *elf_hook(char const *library_filename, char const *function_name, void const *substitution_address);

#ifdef __cplusplus
}
#endif
