cmake_minimum_required(VERSION 3.31)
project(MonitorModeBridge)

set(CMAKE_CXX_STANDARD 20)

file(GLOB SOURCES "Source/*.cpp")
add_library(MonitorModeBridge SHARED ${SOURCES}
        Headers/attributeControl.h
        Headers/WifiRelatedPackets.h
        Headers/NetworkHandler.h
        Source/NetworkHandler.cpp)

target_include_directories(MonitorModeBridge PRIVATE Headers)

find_path(PCAP_INCLUDE_DIR pcap.h)
find_library(PCAP_LIBRARY pcap)

if(PCAP_INCLUDE_DIR AND PCAP_LIBRARY)
    include_directories(${PCAP_INCLUDE_DIR})
    target_link_libraries(MonitorModeBridge PRIVATE ${PCAP_LIBRARY}) #link pcap
endif()