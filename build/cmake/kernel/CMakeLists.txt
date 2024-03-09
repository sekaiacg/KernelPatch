set(TARGET kpimg)
set(TARGET_EXECUTABLE_SUFFIX ".elf")

set(TARGET_CFLAGS
    "-Wall"
    "-fno-builtin"
    "-std=gnu11"
    "-g"
    "-O2"
    "-nostdinc"
    "-fno-PIE"
    ${KERNEL_CFLAGS}
)
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    list(APPEND TARGET_CFLAGS
        "-Wno-return-type"
        "-Wno-invalid-noreturn"
        "-Wno-sometimes-uninitialized"
        "-Wno-unused-function"
#        "-Wno-asm-operand-widths"
        "-Wno-c2x-extensions"
    )
endif ()

set(TARGET_LDFLAGS
    "-nostdlib"
    "-Wl,--no-pie"
    "-static"
    "-T${KERNEL_DIR}/kpimg.lds"
    "-Wl,--no-fatal-warnings"
    "-Wl,--no-gc-sections"
    "-Wl,--build-id=none"
)

set(BASE_SRCS
    setup.c
    setup1.S
    cache.S
    tlsf.c
    start.c
    map.c
    map1.S
    hook.c
    fphook.c
    hmem.c
    predata.c
    symbol.c
    baselib.c
    sha256.c
)
list(TRANSFORM BASE_SRCS PREPEND "${KERNEL_DIR}/base/")

file(GLOB PATCH_SRCS "${KERNEL_DIR}/patch/*.c")
file(GLOB PATCH_COMMON_SRCS "${KERNEL_DIR}/patch/common/*.c")
file(GLOB PATCH_MODULE_SRCS "${KERNEL_DIR}/patch/module/*.c")
file(GLOB PATCH_KSYMS_SRCS "${KERNEL_DIR}/patch/ksyms/*.c")

if (WITH_ANDROID)
    file(GLOB PATCH_ANDROID_SRCS "${KERNEL_DIR}/patch/android/*.c")
    list(APPEND TARGET_CFLAGS "-DANDROID")
    set(KPIMG_NAME "${TARGET}-android")
else ()
    set(KPIMG_NAME "${TARGET}-linux")
endif ()

set(KPIMG_SRCS
    ${BASE_SRCS}
    ${PATCH_SRCS}
    ${PATCH_COMMON_SRCS}
    ${PATCH_MODULE_SRCS}
    ${PATCH_KSYMS_SRCS}
    ${PATCH_ANDROID_SRCS}
)

if (CMAKE_BUILD_TYPE MATCHES "Debug")
    list(APPEND TARGET_CFLAGS "-DDEBUG" "-DMAP_DEBUG")
endif ()

add_executable(${TARGET} ${KPIMG_SRCS})
target_include_directories(${TARGET} PRIVATE ${KERNEL_ALL_INCLUDE})
set_target_properties(${TARGET} PROPERTIES SUFFIX ${TARGET_EXECUTABLE_SUFFIX})
target_compile_options(${TARGET} PRIVATE
    "$<$<COMPILE_LANGUAGE:C>:${TARGET_CFLAGS}>"
    "$<$<COMPILE_LANGUAGE:ASM>:${TARGET_CFLAGS}>"
)
target_link_options(${TARGET} PRIVATE
    "$<$<LINK_LANGUAGE:C>:${TARGET_LDFLAGS}>"
    "$<$<LINK_LANGUAGE:ASM>:${TARGET_LDFLAGS}>"
)
add_custom_command(
    TARGET ${TARGET}
    POST_BUILD
    COMMAND ${CMAKE_OBJCOPY} ARGS -O binary -S "${TARGET}${TARGET_EXECUTABLE_SUFFIX}" "${KPIMG_NAME}"
)
