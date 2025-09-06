cmake_minimum_required(VERSION 4.0)

set(WDK_WINVER "0x0A00")
set(DRIVER_DIR "${PROJECT_SOURCE_DIR}/driver")

file(GLOB_RECURSE DRIVER_SOURCES
    CONFIGURE_DEPENDS
    "${DRIVER_DIR}/*.cpp"
    "${DRIVER_DIR}/*.c"
    "${DRIVER_DIR}/*.h"
)

wdk_add_driver(driver 
    ${DRIVER_SOURCES}
    WINVER ${WDK_WINVER}
)

target_include_directories(driver PRIVATE
    "${DRIVER_DIR}/includes"
    "${DRIVER_DIR}/sharedMemory"
    "${DRIVER_DIR}/physicalMemory"
    "${DRIVER_DIR}/src"
)

#Make DriverEntry the real entrypoint
target_link_options(driver PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/ENTRY:DriverEntry>
)

# Disable stack buffer security checks
target_compile_options(driver PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/GS->
)