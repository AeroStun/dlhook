#include "test.hxx"
#include <cstdio>

int indirect() {
    std::printf(nullptr);
    return direct();
}
