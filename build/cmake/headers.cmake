set(VERSION_HEADER "${PROJECT_ROOT}/version")
set(PATCH_INCLUDE "${KERNEL_DIR}/patch/include")
set(PATCH_INCLUDE_UAPI "${KERNEL_DIR}/patch/include/uapi")
set(KERNEL_INCLUDE "${KERNEL_DIR}/include")
set(KERNEL_LINUX "${KERNEL_DIR}/linux")
set(KERNEL_LINUX_INCLUDE "${KERNEL_DIR}/linux/include")
set(KERNEL_LINUX_ARM64_INCLUDE "${KERNEL_DIR}/linux/arch/arm64/include")
set(KERNEL_LINUX_TOOL_ARM64_INCLUDE "${KERNEL_DIR}/linux/tools/arch/arm64/include")

set(KERNEL_ALL_INCLUDE
    ${PROJECT_ROOT}
    ${KERNEL_DIR}
    ${PATCH_INCLUDE}
    ${KERNEL_INCLUDE}
    ${KERNEL_LINUX}
    ${KERNEL_LINUX_INCLUDE}
    ${KERNEL_LINUX_ARM64_INCLUDE}
    ${KERNEL_LINUX_TOOL_ARM64_INCLUDE}
)

function(print_target_properties target isPrint)
    if(NOT TARGET ${target})
        message("There is no target named '${target}'")
        return()
    endif()

    # this list of properties can be extended as needed
    set(CMAKE_PROPERTY_LIST
        SOURCE_DIR BINARY_DIR
        INCLUDE_DIRECTORIES
        COMPILE_DEFINITIONS
        COMPILE_OPTIONS
        LINK_OPTIONS
        LINK_LIBRARIES
    )

    if (isPrint)
        message("Configuration for target ${target}")
    endif()
    file(WRITE "${CMAKE_BINARY_DIR}/${target}_compile_options.txt" "")
    foreach (prop ${CMAKE_PROPERTY_LIST})
        get_property(propval TARGET ${target} PROPERTY ${prop} SET)
        if (propval)
            get_target_property(propval ${target} ${prop})
            if (isPrint)
                message (STATUS "${prop} = ${propval}")
            endif()
            file(APPEND
                "${CMAKE_BINARY_DIR}/${target}_compile_options.txt"
                "${prop}:      ${propval}\n"
            )
        endif()
    endforeach(prop)
endfunction(print_target_properties)
