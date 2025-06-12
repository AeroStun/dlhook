/*
 * Copyright 2023-2024 AeroStun
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
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>

#if defined(__linux__) && !defined(_GNU_SOURCE)
#    define _GNU_SOURCE
#endif

#if defined(__linux__)
#    include <elf.h>
#    include <fcntl.h>
#    include <link.h>
#elif defined(__QNX__)
#    include <vector>
#    include <sys/elf.h>
#    include <sys/link.h>
#    include <sys/mman.h>
#else
#    error "Unsupported platform"
#endif

#include <dlfcn.h>
#include <unistd.h>

#include "dlhook.h"

#if !defined(R_X86_64_JUMP_SLOT) && defined(R_X86_64_JMP_SLOT)
#    define R_X86_64_JUMP_SLOT R_X86_64_JMP_SLOT
#endif

#if defined __x86_64__ || defined __x86_64
#    define R_JUMP_SLOT R_X86_64_JUMP_SLOT
#    define R_GLOBAL_DATA R_X86_64_GLOB_DAT
#elif defined __aarch64__ || defined __aarch64
#    define R_JUMP_SLOT R_AARCH64_JUMP_SLOT
#    define R_GLOBAL_DATA R_AARCH64_GLOB_DAT
#else
#    error Unsupported platform
#endif

#if defined(__QNX__)
// On QNX this symbol is exported but not exposed
// Forcibly expose it here, with the same decl as on openQNX
extern volatile struct r_debug _r_debug;
#endif

struct MaybeAddr {
    void* addr{nullptr};
    bool valid{false};
};

using DlLinkMap = struct link_map;

struct ObjectPltData {
    std::uintptr_t plt_addr_base{0U};

    const Elf64_Sym* dynsym{nullptr};

    const char* dynstr{nullptr};
    std::size_t dynstr_size{0U};

    const Elf64_Rela* rela_plt{nullptr};
    std::size_t rela_plt_cnt{0U};

    const Elf64_Rela* rela_dyn{nullptr};
    std::size_t rela_dyn_cnt{0U};
};

struct DlHookState {
    std::map<const DlLinkMap*, ObjectPltData> obj_cache{};
#if defined(__linux__)
    int proc_self_mem{0};
#elif defined(__QNX__)
    std::vector<void*> page_cache{};
#endif
};

// Meyer's singleton for the global hooking state
DlHookState& get_state() {
    static DlHookState state{[] {
        DlHookState state;
#if defined(__linux__)
        state.proc_self_mem = ::open("/proc/self/mem", O_RDWR);
#endif
        return state;
    }()};
    return state;
}

static const Elf64_Dyn* find_dyn_by_tag(const Elf64_Dyn* dyn, const Elf64_Sxword tag) {
    for (; dyn->d_tag != DT_NULL; ++dyn) {
        if (dyn->d_tag == tag) {
            return dyn;
        }
    }
    return nullptr;
}

static const DlLinkMap* get_lmap_for_handle(void* const handle) {
    if (handle == nullptr) {
        return _r_debug.r_map;
    }

#if defined(__linux__)
    DlLinkMap* lmap = nullptr;
    const auto dlinfo_res = ::dlinfo(handle, RTLD_DI_LINKMAP, &lmap);
    assert(dlinfo_res == 0);
    return lmap;
#elif defined(__QNX__)
    // Special case; for the current process, the handle points to the objlist
    if (handle == dlopen(nullptr, 0)) {
        return _r_debug.r_map;
    }

    assert(handle != RTLD_DEFAULT);
    assert(handle != RTLD_NEXT);

    return static_cast<DlLinkMap*>(handle);
#else
#    error "Unsupported platform"
#endif
}

template <class T>
static void force_write(T& dst, const T value) {
#if defined(__linux__)
    // Set new target using FOLL_FORCE
    const int proc_self_mem = get_state().proc_self_mem;
    ::lseek64(proc_self_mem, reinterpret_cast<std::intptr_t>(&dst), SEEK_SET);
    ::write(proc_self_mem, &value, sizeof(T));
#elif defined(__QNX__)
    // Get virtual memory page size
    const std::size_t page_size = sysconf(_SC_PAGESIZE);

    // Get base address of the containing page
    void* const aligned_ptr_addr = reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(&dst) & ~(page_size - 1U));

    // Check page cache
    auto& page_cache = get_state().page_cache;
    if (std::find(page_cache.cbegin(), page_cache.cend(), aligned_ptr_addr) == page_cache.cend()) {
        // Force containing page to be writable
        // Since we cannot read the page permissions,
        // we cannot skip this operation if unnecessary on its first hook,
        // nor restore the permissions afterwards.
        // Therfore this is dirty.
        ::mprotect(aligned_ptr_addr, page_size, PROT_READ | PROT_WRITE);
    }

    // Set the new target
    dst = value;
#endif
}

static ObjectPltData inspect_object(DlLinkMap const* obj_lmap) {
    ObjectPltData ret{};

    ret.plt_addr_base = reinterpret_cast<std::uintptr_t>(obj_lmap->l_addr);

    // Locate symbol table
    const Elf64_Dyn* dyn_symtab = find_dyn_by_tag(obj_lmap->l_ld, DT_SYMTAB);
    if (dyn_symtab == nullptr) {
        return {};
    }
    ret.dynsym = reinterpret_cast<const Elf64_Sym*>(dyn_symtab->d_un.d_ptr);

    // Verify Elf_Sym size
    const Elf64_Dyn* dyn_syment = find_dyn_by_tag(obj_lmap->l_ld, DT_SYMENT);
    if (dyn_syment == nullptr || dyn_syment->d_un.d_val != sizeof(Elf64_Sym)) {
        return {};
    }

    // Locate string table
    const Elf64_Dyn* dyn_strtab = find_dyn_by_tag(obj_lmap->l_ld, DT_STRTAB);
    if (dyn_strtab == nullptr) {
        return {};
    }
    ret.dynstr = reinterpret_cast<const char*>(dyn_strtab->d_un.d_ptr);

    // Get string table length
    const Elf64_Dyn* dyn_strsz = find_dyn_by_tag(obj_lmap->l_ld, DT_STRSZ);
    if (dyn_strsz == nullptr) {
        return {};
    }
    ret.dynstr_size = dyn_strsz->d_un.d_val;

    // Try to locate PLT relocs
    const Elf64_Dyn* dyn_jmprel = find_dyn_by_tag(obj_lmap->l_ld, DT_JMPREL);
    if (dyn_jmprel != nullptr) {
        ret.rela_plt = reinterpret_cast<const Elf64_Rela*>(dyn_jmprel->d_un.d_ptr);

        // Get PLT relocs count
        const Elf64_Dyn* dyn_plzrelsz = find_dyn_by_tag(obj_lmap->l_ld, DT_PLTRELSZ);
        if (dyn_plzrelsz == nullptr) {
            return {};
        }
        ret.rela_plt_cnt = dyn_plzrelsz->d_un.d_val / sizeof(Elf64_Rela);
    }

    // Try to locate Rela relocs
    const Elf64_Dyn* dyn_rela = find_dyn_by_tag(obj_lmap->l_ld, DT_RELA);
    if (dyn_rela != nullptr) {
        ret.rela_dyn = reinterpret_cast<const Elf64_Rela*>(dyn_rela->d_un.d_ptr);

        // Get total size of Rela relocs
        const Elf64_Dyn* dyn_relasz = find_dyn_by_tag(obj_lmap->l_ld, DT_RELASZ);
        if (dyn_relasz == nullptr) {
            return {};
        }
        const std::size_t total_size = dyn_relasz->d_un.d_val;

        // Get size of individual Rela relocs
        const Elf64_Dyn* dyn_relaent = find_dyn_by_tag(obj_lmap->l_ld, DT_RELAENT);
        if (dyn_relaent == nullptr) {
            return {};
        }
        const std::size_t elem_size = dyn_relaent->d_un.d_val;
        ret.rela_dyn_cnt = total_size / elem_size;
    }

    if (ret.rela_plt == nullptr && ret.rela_dyn == nullptr) {
        return {};
    }

    return ret;
}

template <class Callback>
static void foreach_plt_or_got(const ObjectPltData& obj, Callback&& callback) {
    auto const filter_relas = [&](const auto& rela, const Elf64_Xword reloc_type) -> bool {
        if (ELF64_R_TYPE(rela.r_info) == reloc_type) {
            // Sanity check of the symbol name's index
            const std::size_t idx = obj.dynsym[ELF64_R_SYM(rela.r_info)].st_name;
            if (idx + 1 > obj.dynstr_size) {
                return false;
            }

            return callback(obj.dynstr + idx, *reinterpret_cast<void**>(obj.plt_addr_base + rela.r_offset));
        }

        return true;
    };

    for (std::size_t i = 0U; i < obj.rela_plt_cnt; ++i) {
        if (!filter_relas(obj.rela_plt[i], R_JUMP_SLOT)) {
            return;
        }
    }

    for (std::size_t i = 0U; i < obj.rela_dyn_cnt; ++i) {
        if (!filter_relas(obj.rela_dyn[i], R_GLOBAL_DATA)) {
            return;
        }
    }
}

static ObjectPltData get_object(const DlLinkMap* lmap) {
    auto& obj_cache = get_state().obj_cache;
    const auto it = obj_cache.find(lmap);
    ObjectPltData object{};
    if (it == obj_cache.end()) {
        object = inspect_object(lmap);
        if (object.dynsym == nullptr) {
            return {};
        }
        obj_cache.emplace(lmap, object);
    } else {
        object = it->second;
    }

    return object;
}

static MaybeAddr dlhook_sym(const DlLinkMap* lmap, const char* const symbol, void* const hook) {
    if (lmap == nullptr) {
        return {};
    }

    auto const symbol_length = std::strlen(symbol);

    MaybeAddr result{};
    const auto callback = [symbol, symbol_length, hook, &result](const char* const name, void*& ptr) -> bool {
        // if (!name.starts_with(symbol))
        if (std::strncmp(name, symbol, symbol_length) != 0) {
            // Keep going
            return true;
        }
        if (name[symbol_length] != '\0' && name[symbol_length] != '@') {
            // Keep going
            return true;
        }

        // Save old target
        result = MaybeAddr{ptr, true};

        // Replace with hook
        force_write(ptr, hook);

        // Success, stop
        return false;
    };
    foreach_plt_or_got(get_object(lmap), callback);

    return result;
}

extern "C" void* dlhook_sym(void* const handle, const char* const symbol, void* const hook) {
    const auto result = dlhook_sym(get_lmap_for_handle(handle), symbol, hook);
    assert(result.valid);
    return result.addr;
}

extern "C" void dlhook_sym_all(const char* symbol, void* hook) {
    for (auto it = _r_debug.r_map; it != nullptr; it = it->l_next) {
        const auto result = dlhook_sym(it, symbol, hook);
        if (!result.valid) {
            continue;
        }
    }
}

static void dlhook_addr(const DlLinkMap* lmap, void* original, void* hook) {
    if (lmap == nullptr) {
        return;
    }

    const auto callback = [original, hook](const char*, void*& ptr) -> bool {
        if (ptr != original) {
            // Keep going
            return true;
        }

        force_write(ptr, hook);

        // Success, stop
        return false;
    };
    foreach_plt_or_got(get_object(lmap), callback);
}

extern "C" void dlhook_addr(void* handle, void* original, void* hook) {
    dlhook_addr(get_lmap_for_handle(handle), original, hook);
}

extern "C" void dlhook_addr_all(void* original, void* hook) {
    for (auto it = _r_debug.r_map; it != nullptr; it = it->l_next) {
        dlhook_addr(it, original, hook);
    }
}
