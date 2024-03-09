set(TARGET kptools)

set(TARGET_CFLAGS
    "-O2"
)

set(TARGET_LDFLAGS
    ${DEFAULT_LDFLAGS}
)

if (NOT CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    list(APPEND TARGET_LDFLAGS "-Wl,--build-id=none")
endif ()

set(KPTOOLS_SRCS
    image.c
    kallsym.c
    kptools.c
    order.c
    insn.c
    patch.c
    symbol.c
    kpm.c
    common.c
    sha256.c
)
list(TRANSFORM KPTOOLS_SRCS PREPEND "${TOOLS_DIR}/")

file(COPY ${KERNEL_INCLUDE}/preset.h DESTINATION ${TOOLS_DIR})

add_executable(${TARGET} ${KPTOOLS_SRCS})

string(TOLOWER "-${CMAKE_SYSTEM_NAME}_${CMAKE_SYSTEM_PROCESSOR}" KPTOOLS_SUFFIX)
set_target_properties(${TARGET} PROPERTIES SUFFIX "${KPTOOLS_SUFFIX}")
target_compile_options(${TARGET} PRIVATE
    "$<$<COMPILE_LANGUAGE:C>:${TARGET_CFLAGS}>"
    "$<$<COMPILE_LANGUAGE:CXX>:${TARGET_CFLAGS}>"
)
target_link_options(${TARGET} PRIVATE
    "$<$<LINK_LANGUAGE:C>:${TARGET_LDFLAGS}>"
    "$<$<LINK_LANGUAGE:CXX>:${TARGET_LDFLAGS}>"
)

#add_custom_command(TARGET ${TARGET} POST_BUILD
#    COMMAND ${CMAKE_STRIP} -w "$<TARGET_FILE:${TARGET}>"
#)