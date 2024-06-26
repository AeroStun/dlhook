#include <cassert>
#include "dlhook.h"
#include "test.hxx"

extern "C" int hook() { return 0xF00L; }

int main() {
    const auto hook_addr = reinterpret_cast<void*>(&hook);

    assert(direct() == 0xBEEF);
    assert(indirect() == 0xBEEF);

    auto* real = dlhook_sym(nullptr, "direct", hook_addr);
    assert(reinterpret_cast<int (*)()>(real)() == 0xBEEF);
    assert(direct() == 0xF00L);
    assert(indirect() == 0xBEEF);

    auto* leftover = dlhook_sym(nullptr, "direct", real);
    assert(leftover == hook_addr);
    assert(direct() == 0xBEEF);
    assert(indirect() == 0xBEEF);

    // dlhook_sym_all("direct", hook_addr);
    // assert(direct() == 0xF00L);
    // assert(indirect() == 0xF00L);

    dlhook_addr(nullptr, real, hook_addr);
    assert(direct() == 0xF00L);
    assert(indirect() == 0xBEEF);

    dlhook_addr(nullptr, hook_addr, real);
    assert(direct() == 0xBEEF);
    assert(indirect() == 0xBEEF);

    dlhook_addr_all(real, hook_addr);
    assert(direct() == 0xF00L);
    assert(indirect() == 0xF00L);
}
