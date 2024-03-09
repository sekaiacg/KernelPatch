cmake_minimum_required(VERSION 3.5...3.27)
project(KernelPatch LANGUAGES C CXX ASM)

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 20)

set(CMAKE_VERBOSE_MAKEFILE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

set(CMAKE_C_OUTPUT_EXTENSION_REPLACE 1)
set(CMAKE_CXX_OUTPUT_EXTENSION_REPLACE 1)
set(CMAKE_ASM_OUTPUT_EXTENSION_REPLACE 1)

# Options
option(DEFAULT_BUILD_RELEASE
    "Build the Release version by default. Turn it off if you want to use CMAKE_BUILD_TYPE. default: ON"
    ON
)
option(WITH_ANDROID "include android support. default: ON" ON)
option(BUILD_KPTOOLS "build kptools. default: ON" ON)
option(BUILD_KPIMG "build kpimg. default: ON" ON)
option(BUILD_KPATCH "build kpatch. default: ON" ON)

# NDK flags
#-g -DANDROID -fdata-sections -ffunction-sections -funwind-tables -fstack-protector-strong -no-canonical-prefixes -D_FORTIFY_SOURCE=2 -Wformat -Werror=format-security
#-Wl,--build-id=sha1 -Wl,--no-undefined-version -Wl,--fatal-warnings -Wl,--gc-sections -Qunused-arguments -Wl,--no-undefined  -Wl,--gc-sections

# Definitions
add_definitions(
    "-D_FILE_OFFSET_BITS=64"
    "-D_LARGEFILE_SOURCE"
    "-D_LARGEFILE64_SOURCE"
)

# Compile flags
if (DEFINED ANDROID_NDK)
    add_definitions("-UANDROID")
    set(CMAKE_C_FLAGS "-v")
    set(CMAKE_CXX_FLAGS "")
    set(CMAKE_ASM_FLAGS "")
    set(CMAKE_EXE_LINKER_FLAGS "")
endif ()

set(GLOBAL_CFLAGS
    "-g"
    "-O2"
)

set(KERNEL_CFLAGS
    "-fno-PIC"
    "-fno-asynchronous-unwind-tables"
    "-fno-stack-protector"
)

set(DEFAULT_CFLAGS
    "-fdata-sections"
    "-ffunction-sections"
    "-funwind-tables"
    "-fstack-protector-strong"
    "-no-canonical-prefixes"
    "-D_FORTIFY_SOURCE=2 "
    "-Wformat"
    "-Werror=format-security"
)

set(DEFAULT_LDFLAGS
    "-fstack-protector-strong"
)
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    list(APPEND DEFAULT_LDFLAGS "-Qunused-arguments")
endif ()

if (DEFAULT_BUILD_RELEASE)
    set(CMAKE_BUILD_TYPE "Release")
else (NOT CMAKE_BUILD_TYPE MATCHES "Debug")
    set(CMAKE_BUILD_TYPE "Debug")
    list(APPEND GLOBAL_CFLAGS "-O0" "-DDEBUG")
endif ()

message(STATUS "[KernelPatch] Build type is ${CMAKE_BUILD_TYPE}")
message(STATUS "[KernelPatch] WITH_ANDROID is ${WITH_ANDROID}")

if (CMAKE_SYSTEM_NAME MATCHES "Android|Linux")
    list(APPEND DEFAULT_LDFLAGS "-Wl,--gc-sections")
    list(APPEND DEFAULT_LDFLAGS "-Wl,--build-id=sha1,--no-undefined,--no-undefined-version,--fatal-warnings")
    if (CMAKE_SYSTEM_NAME STREQUAL "Android")
        list(APPEND DEFAULT_CFLAGS "-mllvm" "-polly")
    endif ()
elseif (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    #list(APPEND DEFAULT_LDFLAGS "-Wl,-dead_strip,-S,-x")
elseif (CMAKE_SYSTEM_NAME MATCHES "Windows")
    list(APPEND GLOBAL_CFLAGS "-static")
    list(APPEND DEFAULT_LDFLAGS "-Wl,--gc-sections")
endif ()

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    list(APPEND GLOBAL_CFLAGS "-fdiagnostics-color=always")
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    list(APPEND GLOBAL_CFLAGS "-fcolor-diagnostics")
endif ()

add_compile_options(
    "$<$<COMPILE_LANGUAGE:C>:${GLOBAL_CFLAGS}>"
    "$<$<COMPILE_LANGUAGE:CXX>:${GLOBAL_CFLAGS}>"
    "$<$<COMPILE_LANGUAGE:ASM>:${GLOBAL_CFLAGS}>"
)

set(KERNEL_DIR "${PROJECT_SOURCE_DIR}/../../kernel")
set(TOOLS_DIR "${PROJECT_SOURCE_DIR}/../../tools")
set(USER_DIR "${PROJECT_SOURCE_DIR}/../../user")
set(KPM_DIR "${PROJECT_SOURCE_DIR}/../../kpm-demo")
set(PROJECT_ROOT "${PROJECT_SOURCE_DIR}/../..")

# headers
include(headers.cmake)

# Start building
if (BUILD_KPTOOLS)
    add_subdirectory(tools)
endif ()
if (CMAKE_SYSTEM_NAME MATCHES "Android|Linux" AND CMAKE_SYSTEM_PROCESSOR STREQUAL "aarch64")
    if (BUILD_KPIMG)
        add_subdirectory(kernel)
    endif ()
    if (BUILD_KPATCH)
        add_subdirectory(user)
    endif ()
    add_subdirectory(kpm)
endif ()
