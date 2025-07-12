cmake_minimum_required(VERSION 3.31)
project(MonitorModeBridge)
set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_STANDARD 20)

# Source files
file(GLOB SOURCES "Source/*.cpp")
add_library(MonitorModeBridge SHARED ${SOURCES})

# Include paths
target_include_directories(MonitorModeBridge PUBLIC Headers Libs)

add_library(libwifi SHARED IMPORTED)
set_target_properties(libwifi PROPERTIES IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/Libs/libwifi.so)

add_library(libcrypto SHARED IMPORTED)
set_target_properties(libcrypto PROPERTIES IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/Libs/libcrypto.so)

target_link_libraries(MonitorModeBridge PRIVATE libwifi libcrypto)

# Find and link libpcap if available
find_path(PCAP_INCLUDE_DIR pcap.h)
find_library(PCAP_LIBRARY pcap)

if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
    target_include_directories(MonitorModeBridge PRIVATE ${PCAP_INCLUDE_DIR})
    target_link_libraries(MonitorModeBridge PRIVATE ${PCAP_LIBRARY})
else()
    message(FATAL_ERROR "libpcap not found — MonitorModeBridge will build without it.")
endif()

add_executable(Loader Loader/main.cpp)
target_include_directories(Loader PUBLIC Libs)
target_link_libraries(Loader PUBLIC MonitorModeBridge libwifi)
