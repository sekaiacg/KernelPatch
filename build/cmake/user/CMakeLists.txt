set(TARGET_CFLAGS ${DEFAULT_CFLAGS})
if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    list(APPEND TARGET_CFLAGS "-D_GNU_SOURCE")
endif ()

set(TARGET_LDFLAGS ${DEFAULT_LDFLAGS})

#######################################libkpatch and kpatch##########################################
set(TARGET kpatch_static)
set(LIBKPATCH_SRCS
    kpatch.c
    kpm.c
    su.c
)
list(TRANSFORM LIBKPATCH_SRCS PREPEND "${USER_DIR}/")

if (CMAKE_SYSTEM_NAME STREQUAL "Android" AND WITH_ANDROID)
    file(GLOB KPATCH_ANDROID_SRCS "${USER_DIR}/android/*.c")
    list(APPEND LIBKPATCH_SRCS ${KPATCH_ANDROID_SRCS})
    list(APPEND TARGET_CFLAGS "-DANDROID")
    set(KPATCH_SUFFIX "-android")
elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux" AND NOT WITH_ANDROID)
    set(KPATCH_SUFFIX "-linux")
endif ()

if (DEFINED KPATCH_SUFFIX)
    file(COPY ${PATCH_INCLUDE_UAPI} DESTINATION ${USER_DIR})

    add_library(${TARGET} STATIC ${LIBKPATCH_SRCS})
    target_compile_options(${TARGET} PRIVATE "$<$<COMPILE_LANGUAGE:C>:${TARGET_CFLAGS}>")
    target_link_options(${TARGET} PRIVATE "$<$<LINK_LANGUAGE:C>:${TARGET_LDFLAGS}>")

    set(TARGET kpatch)
    set(KPATCH_SRCS main.c)
    list(TRANSFORM KPATCH_SRCS PREPEND "${USER_DIR}/")

    add_executable(${TARGET} ${KPATCH_SRCS})
    set_target_properties(${TARGET} PROPERTIES SUFFIX "${KPATCH_SUFFIX}")
    target_include_directories(${TARGET} PRIVATE ${USER_DIR})
    target_link_libraries(${TARGET} kpatch_static)
    target_compile_options(${TARGET} PRIVATE "$<$<COMPILE_LANGUAGE:C>:${TARGET_CFLAGS}>")
    target_link_options(${TARGET} PRIVATE "$<$<LINK_LANGUAGE:C>:${TARGET_LDFLAGS}>")
endif ()
###############################################################################################

########################################libapjni.so#########################################
if (CMAKE_SYSTEM_NAME STREQUAL "Android" AND WITH_ANDROID)
    set(TARGET apjni)
    add_library(${TARGET} SHARED ${USER_DIR}/android/apjni.cpp)
    target_include_directories(${TARGET} PRIVATE ${USER_DIR})
    target_link_libraries(${TARGET} log)
    target_compile_options(${TARGET} PRIVATE
        "$<$<COMPILE_LANGUAGE:C>:${TARGET_CFLAGS}>"
        "$<$<COMPILE_LANGUAGE:CXX>:${TARGET_CFLAGS}>"
    )
    target_link_options(${TARGET} PRIVATE
        "$<$<LINK_LANGUAGE:C>:${TARGET_LDFLAGS}>"
        "$<$<LINK_LANGUAGE:CXX>:${TARGET_LDFLAGS}>"
    )
endif ()
###########################################################################################
