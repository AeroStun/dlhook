# dlhook

An extension to the dlfcn.h family, for attaching hooks to functions from DSOs.

Requires C++14 to build, but the interface is C compatible.

Supported platforms:
- Linux amd64 (manually tested), aarch64 (untested yet)
- QNX aarch64 (untested yet)

Synopsis:
```cpp
// Hook by symbol

/// Hooks the PLT entry of @a symbol with @a hook in @a handle.
///
/// @param handle result of a successful call to dlopen(),
///               or @a nullptr for the running executable.
/// @param symbol which symbol to hook in the PLT of @a handle.
/// @param hook replacement entry for @a symbol.
/// @return the original address found in the PLT
/// @note if an error occurs, the program will be aborted
void* dlhook_sym(void* handle, const char* symbol, void* hook);

/// Hooks the PLT entries of @a symbol with @a hook in all currently loaded objects.
///
/// @param symbol which symbol to hook in the PLT of @a handle.
/// @param hook replacement entry for @a symbol.
/// @note if an error occurs, it will be safely ignored.
void dlhook_sym_all(const char* symbol, void* hook);

// Hook by address

/// Replaces all PLT entries pointing to @a original by @a hook in @a handle
///
/// @param handle result of a successful call to dlopen(),
///               or @a nullptr for the running executable.
/// @param original address to replace.
/// @param hook replacement address.
/// @note if an error occurs, the program will be aborted.
void dlhook_addr(void* handle, void* original, void* hook);

/// Replaces all PLT entries pointing to @a original by @a hook in all currently loaded objects.
///
/// @param original address to replace.
/// @param hook replacement address.
/// @note if an error occurs, the program will be aborted.
void dlhook_addr_all(void* original, void* hook);
```

