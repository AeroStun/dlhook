cmake_minimum_required (VERSION 3.16)

project (dlhook)

add_library (dlhook SHARED)
target_compile_features (dlhook PRIVATE cxx_std_14)
target_include_directories (dlhook PUBLIC include)
target_sources (dlhook PRIVATE src/dlhook.cxx include/dlhook.h)

if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
  include (CTest)
  if (BUILD_TESTING)
    add_subdirectory (test)
  endif ()
endif ()
