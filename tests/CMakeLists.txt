cmake_minimum_required(VERSION 3.16)
project(ticket_tests CXX)
set(CMAKE_CXX_STANDARD 17)

find_package(CURL REQUIRED)

add_executable(run_tests run_tests.cpp)
target_link_libraries(run_tests PRIVATE CURL::libcurl)
