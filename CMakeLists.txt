cmake_minimum_required(VERSION 3.8)
project(Original)
include_directories(/usr/include/openssl/)
link_libraries(ssl)
link_libraries(crypto)
set(CMAKE_CXX_STANDARD 11)

set(SOURCE_FILES main.cpp IntegrityTree.h  TrustedArea.h m_stdio.h openSSLWraps.h )
add_executable(Original ${SOURCE_FILES})



