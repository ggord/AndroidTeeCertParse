cmake_minimum_required(VERSION 3.23.2)
project(AndroidTeeCert)

set(CMAKE_CXX_STANDARD 17)

add_executable(AndroidTeeCert main.cpp zLog.cpp zTeeCert.cpp)
