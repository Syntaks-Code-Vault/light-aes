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

add_executable("test_vectors" "test_vectors.c" ${AES_SOURCES})

target_include_directories("test_vectors" PRIVATE ${AES_HEADERS})