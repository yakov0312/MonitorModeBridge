cmake_minimum_required(VERSION 3.31)
project(MonitorModeBridge)
set(CMAKE_BUILD_TYPE Debug)

set(CMAKE_CXX_STANDARD 20)

# Source files
file(GLOB SOURCES "Source/*.cpp")
add_library(MonitorModeBridge SHARED ${SOURCES})

# Include paths
target_include_directories(MonitorModeBridge PRIVATE Headers Libs)

# Link statically to libwifi.a
add_library(wifi STATIC IMPORTED)
set_target_properties(wifi PROPERTIES
        IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/Libs/libwifi.a
        INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_SOURCE_DIR}/Libs
)

add_library(crypto STATIC IMPORTED)
set_target_properties(crypto PROPERTIES
        IMPORTED_LOCATION ${CMAKE_SOURCE_DIR}/Libs/libcrypto.a
        INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_SOURCE_DIR}/Libs
)


# Link libwifi
target_link_libraries(MonitorModeBridge PRIVATE wifi)

# Find and link libpcap if available
find_path(PCAP_INCLUDE_DIR pcap.h)
find_library(PCAP_LIBRARY pcap)

if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
    target_include_directories(MonitorModeBridge PRIVATE ${PCAP_INCLUDE_DIR})
    target_link_libraries(MonitorModeBridge PRIVATE ${PCAP_LIBRARY})
else()
    message(WARNING "libpcap not found — MonitorModeBridge will build without it.")
endif()

add_executable(Loader Loader/main.cpp)
target_link_libraries(Loader PRIVATE MonitorModeBridge)
