cmake_minimum_required(VERSION 4.0)

project(driver)

set(CMAKE_CXX_STANDARD 20)
set_property(GLOBAL PROPERTY USER_FOLDERS ON)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")
find_package(WDK REQUIRED)

add_subdirectory(driver)
add_subdirectory(client)
