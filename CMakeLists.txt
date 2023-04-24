cmake_minimum_required (VERSION 3.16)

project (dlhook)

add_library (dlhook SHARED)
target_compile_features (dlhook PRIVATE cxx_std_17)
target_include_directories (dlhook PUBLIC include)
target_compile_options (dlhook PRIVATE -Wno-pointer-arith)
target_sources (dlhook PRIVATE src/dlhook.cxx include/dlhook.hxx)

if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
  include (CTest)
  if (BUILD_TESTING)
    add_subdirectory (test)
  endif ()
endif ()
