cmake_minimum_required(VERSION 3.31)

project(MonitorModeBridge LANGUAGES C CXX)

# ---------------------------------------------------------------------------
# Global settings
# ---------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# compile_commands.json for clangd / IDEs
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

# ---------------------------------------------------------------------------
# System dependencies (Fedora: libnl3-devel libpcap-devel)
# ---------------------------------------------------------------------------
find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

pkg_check_modules(LIBNL REQUIRED IMPORTED_TARGET libnl-3.0 libnl-genl-3.0 libnl-route-3.0)
pkg_check_modules(LIBPCAP REQUIRED IMPORTED_TARGET libpcap)

# ---------------------------------------------------------------------------
# Bundled dependencies (Libs/): libwifi and OpenSSL, headers + shared libs
# ---------------------------------------------------------------------------
add_library(libwifi SHARED IMPORTED)
set_target_properties(libwifi PROPERTIES
        IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/Libs/libwifi.so"
        INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/Libs"
)

add_library(libcrypto SHARED IMPORTED)
set_target_properties(libcrypto PROPERTIES
        IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/Libs/libcrypto.so"
        INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/Libs"
)

# ---------------------------------------------------------------------------
# Bridge library: every .cpp/.h under Bridge/ is picked up automatically.
# CONFIGURE_DEPENDS re-runs the glob on each build, so new files need no
# change here.
# ---------------------------------------------------------------------------
file(GLOB_RECURSE BRIDGE_SOURCES CONFIGURE_DEPENDS
        "${CMAKE_SOURCE_DIR}/Bridge/*.cpp"
        "${CMAKE_SOURCE_DIR}/Bridge/*.c"
)
file(GLOB_RECURSE BRIDGE_HEADERS CONFIGURE_DEPENDS
        "${CMAKE_SOURCE_DIR}/Bridge/*.h"
        "${CMAKE_SOURCE_DIR}/Bridge/*.hpp"
)

add_library(MonitorModeBridge SHARED
        ${BRIDGE_SOURCES}
        ${BRIDGE_HEADERS}
)

# PUBLIC: headers of the bridge include libwifi/OpenSSL/libnl headers, so
# whatever links the bridge (Loader) gets these include paths too.
target_include_directories(MonitorModeBridge PUBLIC
        ${CMAKE_SOURCE_DIR}/Bridge
)

target_link_libraries(MonitorModeBridge
        PUBLIC
            libwifi
            libcrypto
            PkgConfig::LIBNL
            PkgConfig::LIBPCAP
        PRIVATE
            Threads::Threads
)

# ---------------------------------------------------------------------------
# Loader executable: every .cpp/.h under Loader/ is picked up automatically
# ---------------------------------------------------------------------------
file(GLOB_RECURSE LOADER_SOURCES CONFIGURE_DEPENDS
        "${CMAKE_SOURCE_DIR}/Loader/*.cpp"
        "${CMAKE_SOURCE_DIR}/Loader/*.h"
)

add_executable(Loader
        ${LOADER_SOURCES}
)

target_link_libraries(Loader PRIVATE
        MonitorModeBridge
)
