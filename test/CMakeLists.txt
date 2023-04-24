
add_library (direct SHARED direct.cxx)

add_library (indirect SHARED indirect.cxx)
target_link_libraries (indirect PRIVATE direct)

add_executable (dlhook_test test.cxx)
target_link_libraries (dlhook_test PRIVATE dlhook direct indirect)

add_test (NAME dlhook_test COMMAND dlhook_test)
