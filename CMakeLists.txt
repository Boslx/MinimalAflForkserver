cmake_minimum_required(VERSION 3.29)
project(MinimalAflForkserver C)

set(CMAKE_C_STANDARD 11)

add_executable(forkserver forkserver.c
)

add_executable(forkserverRunner forkserverRunner.c
)
