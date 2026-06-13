cmake_minimum_required(VERSION 3.16)
project(ticket_system CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Find packages ──────────────────────────────────────────────────────────────
find_package(PkgConfig REQUIRED)

# Crow (header-only, fetched via FetchContent or installed)
find_path(CROW_INCLUDE_DIR crow.h PATHS /usr/include /usr/local/include)

# libpqxx
pkg_check_modules(PQXX REQUIRED libpqxx)

# OpenSSL (required by jwt-cpp)
find_package(OpenSSL REQUIRED)

# Threads
find_package(Threads REQUIRED)

# Boost (Crow uses Boost.Asio)
find_package(Boost REQUIRED COMPONENTS system)

# ── Executable ────────────────────────────────────────────────────────────────
add_executable(ticket_server src/main.cpp)

target_include_directories(ticket_server PRIVATE
    ${CROW_INCLUDE_DIR}
    ${PQXX_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
    ${Boost_INCLUDE_DIRS}
    /usr/local/include          # jwt-cpp, bcrypt, nlohmann/json
    /usr/include
)

target_link_libraries(ticket_server PRIVATE
    ${PQXX_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
    ${Boost_LIBRARIES}
    bcrypt
)

target_compile_definitions(ticket_server PRIVATE CROW_ENABLE_SSL)

# ── Install ────────────────────────────────────────────────────────────────────
install(TARGETS ticket_server DESTINATION bin)
