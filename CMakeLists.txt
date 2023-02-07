cmake_minimum_required(VERSION 3.22)
project(aes)

set(AES_SOURCES
    aes/core.c
    aes/ecb.c
    aes/tools.c
)

set(AES_HEADERS
    aes
)

add_executable(${PROJECT_NAME} "main.c" ${AES_SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE ${AES_HEADERS})