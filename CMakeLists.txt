cmake_minimum_required(VERSION 3.18)

project(messenger)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(THREADS_PREFER_PTHREAD_FLAG ON)

find_package(Threads REQUIRED)
find_package(SQLite3 REQUIRED)
find_package(OpenSSL REQUIRED)

set(SOURCE_FILES

    main.cpp
    vendor/asio/include/asio.hpp
    vendor/asio/include/asio/ts/buffer.hpp
    vendor/asio/include/asio/ts/internet.hpp
)

include_directories(vendor/asio/include)

add_executable(messenger ${SOURCE_FILES}
    backup
    backupwithdelimeter)

target_link_libraries(messenger PRIVATE
    Threads::Threads
    SQLite::SQLite3
    OpenSSL::SSL
    OpenSSL::Crypto)
