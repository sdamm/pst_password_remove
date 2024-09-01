CMAKE_MINIMUM_REQUIRED(VERSION 3.24)

project(pst_password_remove)

add_subdirectory(microsoft_pst)

#add_library(libpst libpst/libpst.c libpst/debug.c libpst/vbuf.c libpst/libstrfunc.c libpst/timeconv.c)
add_library(libpst INTERFACE)
target_include_directories(libpst INTERFACE /usr/include/libpst-4)
target_link_libraries(libpst INTERFACE z)
target_link_libraries(libpst INTERFACE pst)

add_executable(${PROJECT_NAME}
	src/main.cpp
	src/libpst_extension.c
	include/libpst_internal.h
	src/libpst_internal.c
	include/libpst_extension.h)
target_link_libraries(${PROJECT_NAME} PUBLIC libpst microsoft_pst)
target_include_directories(${PROJECT_NAME} PUBLIC include)
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 20)
