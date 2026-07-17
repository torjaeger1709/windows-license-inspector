cmake_minimum_required(VERSION 3.20)

project(LicenseInspector
    VERSION 1.0.0
    DESCRIPTION "Digital Forensics & Windows/Office License Crack Detector"
    LANGUAGES CXX
)

if(NOT WIN32)
    message(FATAL_ERROR "LicenseInspector only supports Windows (MSVC toolchain).")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(SOURCES
    src/main.cpp
    src/common/utils.cpp
    src/ui/console_ui.cpp
    src/core/registry_query.cpp
    src/core/wmi_query.cpp
    src/core/service_query.cpp
    src/core/event_log_query.cpp
    src/core/sys_path.cpp
    src/core/dlv_collector.cpp
    src/core/license_cache.cpp
    src/modules/module_a_windows.cpp
    src/modules/module_b_office.cpp
)

add_executable(license-inspector ${SOURCES})

target_include_directories(license-inspector PRIVATE
    ${CMAKE_SOURCE_DIR}/src
)

target_compile_definitions(license-inspector PRIVATE
    UNICODE
    _UNICODE
    _WIN32_WINNT=0x0A00
    WIN32_LEAN_AND_MEAN
    NOMINMAX
)

if(MSVC)
    target_compile_options(license-inspector PRIVATE
        /W4         # Warning level 4
        /WX-        # Warnings are NOT errors (we use some winapi casts)
        /MP         # Multi-processor compilation
        /utf-8      # Source files are UTF-8
        /Zc:__cplusplus  # Correct __cplusplus macro reporting
    )

    set_target_properties(license-inspector PROPERTIES
        LINK_FLAGS "/SUBSYSTEM:CONSOLE /MANIFEST:EMBED /MANIFESTUAC:NO /MANIFESTINPUT:${CMAKE_SOURCE_DIR}/src/license-inspector.manifest"
    )
endif()

target_link_libraries(license-inspector PRIVATE
    wbemuuid
    ole32
    oleaut32
    taskschd
    shlwapi
    advapi32
    bcrypt
)

install(TARGETS license-inspector DESTINATION bin)

message(STATUS "=== License Inspector Build Configuration ===")
message(STATUS "  CMake version  : ${CMAKE_VERSION}")
message(STATUS "  Generator      : ${CMAKE_GENERATOR}")
message(STATUS "  Build type     : ${CMAKE_BUILD_TYPE}")
message(STATUS "  C++ standard   : C++${CMAKE_CXX_STANDARD}")
message(STATUS "  Output binary  : license-inspector.exe")
message(STATUS "=============================================")
