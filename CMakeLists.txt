cmake_minimum_required(VERSION 3.31)

project(MonitorModeBridge)

# Global settings
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# Bridge library
file(GLOB_RECURSE BRIDGE_SOURCES CONFIGURE_DEPENDS
        "${CMAKE_SOURCE_DIR}/Bridge/*.cpp"
)

add_library(MonitorModeBridge SHARED
        ${BRIDGE_SOURCES}
)

target_include_directories(MonitorModeBridge PUBLIC
        ${CMAKE_SOURCE_DIR}/Bridge
        ${CMAKE_SOURCE_DIR}/Libs
)

# Imported libraries
add_library(libwifi SHARED IMPORTED)
set_target_properties(libwifi PROPERTIES
        IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/Libs/libwifi.so"
)

add_library(libcrypto SHARED IMPORTED)
set_target_properties(libcrypto PROPERTIES
        IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/Libs/libcrypto.so"
)

# libpcap
find_path(PCAP_INCLUDE_DIR pcap.h)
find_library(PCAP_LIBRARY pcap)

if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap not found")
endif()

target_include_directories(MonitorModeBridge PRIVATE
        ${PCAP_INCLUDE_DIR}
)

# Link Bridge
target_link_libraries(MonitorModeBridge PRIVATE
        libwifi
        libcrypto
        ${PCAP_LIBRARY}
)

# Loader
add_executable(Loader
        Loader/main.cpp
)

target_include_directories(Loader PUBLIC
        ${CMAKE_SOURCE_DIR}/Bridge
        ${CMAKE_SOURCE_DIR}/Libs
)

target_link_libraries(Loader PUBLIC
        MonitorModeBridge
        libwifi
)