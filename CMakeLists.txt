cmake_minimum_required(VERSION 3.16)

project(VehiclesExtended LANGUAGES CXX)

if (MSVC)
    if (NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
        message(FATAL_ERROR "You MUST build this as Win32 (x86), not x64.")
    endif()
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -m32")
endif()


add_library(VehiclesExtended SHARED
    src/main.cpp
)

set_target_properties(VehiclesExtended PROPERTIES
    PREFIX ""
    SUFFIX ".asi"
)

target_compile_features(VehiclesExtended PRIVATE cxx_std_17)

# Disable exceptions / RTTI (optional but common for ASI)
target_compile_options(VehiclesExtended PRIVATE
    $<$<CXX_COMPILER_ID:MSVC>:/EHs-c- /GR->
    $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-fno-exceptions -fno-rtti>
)

target_compile_definitions(VehiclesExtended PRIVATE
    WIN32
    _WINDOWS
    _USRDLL
)

if (MSVC)
    set_property(TARGET VehiclesExtended PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded"
    )
endif()