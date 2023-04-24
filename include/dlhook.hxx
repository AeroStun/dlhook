/*
 * Copyright 2023 AeroStun
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef DLHOOK_HXX
#define DLHOOK_HXX

#include <string_view>

// Hook by symbol

/// Hooks the PLT entry of @a symbol with @a hook in @a handle.
///
/// @param handle result of a successful call to dlopen(),
///               or @a nullptr for the running executable.
/// @param symbol which symbol to hook in the PLT of @a handle.
/// @param hook replacement entry for @a symbol.
/// @return the original address found in the PLT
/// @note if an error occurs, the program will be aborted
void* dlhook_sym(void* handle, std::string_view symbol, void* hook);

/// Hooks the PLT entries of @a symbol with @a hook in all currently loaded objects.
///
/// @param symbol which symbol to hook in the PLT of @a handle.
/// @param hook replacement entry for @a symbol.
/// @note if an error occurs, it will be safely ignored.
void dlhook_sym_all(std::string_view symbol, void* hook);

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

#endif
