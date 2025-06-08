cmake_minimum_required(VERSION 3.10)
project(DLLInjector LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    message(STATUS "Configuring Debug build")
    add_compile_options(-g -O0 -DDEBUG)
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
    message(STATUS "Configuring Release build")
    add_compile_options(-O3 -DNDEBUG)
endif()

# dlltest 注入测试模块
add_library(dlltest SHARED dlltest.c)
# 指定输出文件名
set_target_properties(dlltest PROPERTIES
    OUTPUT_NAME "dlltest"
    PREFIX ""                             # 去掉前缀 "lib"
)

# HideWindow 模块
add_library(HideWindow SHARED HideWindow.c)
# 指定输出文件名
set_target_properties(HideWindow PROPERTIES
    OUTPUT_NAME "HideWindow"
    PREFIX ""                             # 去掉前缀 "lib"
)

# ShowWindow 模块
add_library(ShowWindow SHARED ShowWindow.c)
# 指定输出文件名
set_target_properties(ShowWindow PROPERTIES
    OUTPUT_NAME "ShowWindow"
    PREFIX ""                             # 去掉前缀 "lib"
)

# 可执行文件 DLLInjector
add_executable(DLLInjector DLLInjector.cpp)
# 链接库
target_link_libraries(DLLInjector PRIVATE kernel32 ntdll -static-libgcc -static-libstdc++)

# 可执行文件 CheckHide
add_executable(CheckHide CheckHide.c)
# 链接库
target_link_libraries(CheckHide PRIVATE kernel32 -static-libgcc -static-libstdc++)