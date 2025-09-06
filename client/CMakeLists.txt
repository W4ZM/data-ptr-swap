cmake_minimum_required(VERSION 4.0)

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

file(GLOB_RECURSE SRC_FILES 
    ${PROJECT_SOURCE_DIR}/client/src/*.cpp 
    ${PROJECT_SOURCE_DIR}/client/src/*.h
)

add_executable(client ${SRC_FILES})

target_include_directories(client PRIVATE "${PROJECT_SOURCE_DIR}/driver/sharedMemory")

set_target_properties(client PROPERTIES
    LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
)