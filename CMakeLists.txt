cmake_minimum_required(VERSION 3.31)

project(MonitorModeBridge)

# Global settings
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# Find pkg-config first (needed for libnl)
find_package(PkgConfig REQUIRED)

# libnl (must be defined before usage)
pkg_check_modules(NL3 REQUIRED libnl-3.0)
pkg_check_modules(NLGENL REQUIRED libnl-genl-3.0)
pkg_check_modules(NLROUTE REQUIRED libnl-route-3.0)

# Bridge library sources
file(GLOB_RECURSE BRIDGE_SOURCES CONFIGURE_DEPENDS
        "${CMAKE_SOURCE_DIR}/Bridge/*.cpp"
)

add_library(MonitorModeBridge SHARED
        ${BRIDGE_SOURCES}
)

# Include directories (portable via pkg-config)
target_include_directories(MonitorModeBridge PUBLIC
        ${CMAKE_SOURCE_DIR}/Bridge
        ${CMAKE_SOURCE_DIR}/Libs
        ${NL3_INCLUDE_DIRS}
        ${NLGENL_INCLUDE_DIRS}
        ${NLROUTE_INCLUDE_DIRS}
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
    message(FATAL_ERROR "libpcap not found (install libpcap-devel)")
endif()

target_include_directories(MonitorModeBridge PRIVATE
        ${PCAP_INCLUDE_DIR}
)

# Link libraries (IMPORTANT: libnl included here)
target_link_libraries(MonitorModeBridge PRIVATE
        libwifi
        libcrypto
        ${PCAP_LIBRARY}
        ${NL3_LIBRARIES}
        ${NLGENL_LIBRARIES}
        ${NLROUTE_LIBRARIES}
)

# Loader executable
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