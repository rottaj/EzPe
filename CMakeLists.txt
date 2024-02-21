cmake_minimum_required(VERSION 3.27)
project(PE_Parser C)

set(CMAKE_C_STANDARD 11)


include_directories(/usr/x86_64-w64-mingw32/include/)

add_executable(PE_Parser
        EzPz.c)
