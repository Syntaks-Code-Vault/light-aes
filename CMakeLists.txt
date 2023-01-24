cmake_minimum_required(VERSION 3.25)
project(light-aes)

add_executable(${PROJECT_NAME} "main.c")
# add_library(${PROJECT_NAME} "")

target_sources(${PROJECT_NAME}
    PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/aes/core.c
        ${CMAKE_CURRENT_LIST_DIR}/aes/ecb.c
        ${CMAKE_CURRENT_LIST_DIR}/aes/tools.c
    INTERFACE
        ${CMAKE_CURRENT_LIST_DIR}/aes/core.h
        ${CMAKE_CURRENT_LIST_DIR}/aes/ecb.h
        ${CMAKE_CURRENT_LIST_DIR}/aes/tools.h
)

target_include_directories(${PROJECT_NAME}
    INTERFACE
        ${CMAKE_CURRENT_LIST_DIR}/aes
)