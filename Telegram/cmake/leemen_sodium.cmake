include_guard(GLOBAL)

include(FetchContent)
include(ExternalProject)

if(POLICY CMP0135)
    cmake_policy(SET CMP0135 NEW)
endif()

set(LEEMEN_SODIUM_ARCHIVE "" CACHE FILEPATH
    "Optional offline copy of the pinned official libsodium source archive")
set(leemen_sodium_url
    "https://github.com/jedisct1/libsodium/releases/download/1.0.22-RELEASE/libsodium-1.0.22.tar.gz")
if(LEEMEN_SODIUM_ARCHIVE)
    set(leemen_sodium_url "${LEEMEN_SODIUM_ARCHIVE}")
endif()

FetchContent_Declare(leemen_sodium_source
    URL "${leemen_sodium_url}"
    URL_HASH SHA256=adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349
    DOWNLOAD_NO_PROGRESS TRUE
    TLS_VERIFY TRUE
)
FetchContent_MakeAvailable(leemen_sodium_source)

set(leemen_sodium_root "${CMAKE_BINARY_DIR}/_deps/leemen-sodium-build")
set(leemen_sodium_config "$<IF:$<BOOL:$<CONFIG>>,$<CONFIG>,Debug>")
file(MAKE_DIRECTORY "${leemen_sodium_root}/include/sodium")
configure_file(
    "${leemen_sodium_source_SOURCE_DIR}/builds/msvc/version.h"
    "${leemen_sodium_root}/include/sodium/version.h"
    COPYONLY
)
configure_file(
    "${leemen_sodium_source_SOURCE_DIR}/src/libsodium/include/sodium/export.h"
    "${leemen_sodium_root}/include/sodium/export.h"
    COPYONLY
)

set(leemen_sodium_build_args)
if(WIN32)
    if(NOT MSVC)
        message(FATAL_ERROR "Leemen libsodium on Windows requires the MSVC toolchain.")
    endif()
    if(CMAKE_VS_MSBUILD_COMMAND)
        set(leemen_sodium_msbuild "${CMAKE_VS_MSBUILD_COMMAND}")
    else()
        find_program(leemen_sodium_msbuild NAMES MSBuild.exe MSBuild REQUIRED)
    endif()
    if(CMAKE_VS_PLATFORM_NAME)
        set(leemen_sodium_platform "${CMAKE_VS_PLATFORM_NAME}")
    elseif(CMAKE_CXX_COMPILER_ARCHITECTURE_ID MATCHES "^(ARM64|arm64)$"
            OR CMAKE_SYSTEM_PROCESSOR MATCHES "^(ARM64|arm64|aarch64)$")
        set(leemen_sodium_platform ARM64)
    elseif(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(leemen_sodium_platform x64)
    else()
        set(leemen_sodium_platform Win32)
    endif()
    if(NOT leemen_sodium_platform MATCHES "^(Win32|x64|ARM64)$")
        message(FATAL_ERROR "Unsupported libsodium MSVC platform: ${leemen_sodium_platform}")
    endif()
    set(leemen_sodium_runtime "${CMAKE_MSVC_RUNTIME_LIBRARY}")
    if(NOT leemen_sodium_runtime)
        set(leemen_sodium_runtime "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
    endif()
    file(GENERATE
        OUTPUT "${leemen_sodium_root}/runtime-${leemen_sodium_config}.props"
        CONTENT "<Project xmlns=\"http://schemas.microsoft.com/developer/msbuild/2003\"><ItemDefinitionGroup><ClCompile><RuntimeLibrary>${leemen_sodium_runtime}</RuntimeLibrary></ClCompile></ItemDefinitionGroup></Project>\n"
    )
    list(APPEND leemen_sodium_build_args
        "-DLEEMEN_SODIUM_MSBUILD=${leemen_sodium_msbuild}"
        "-DLEEMEN_SODIUM_PLATFORM=${leemen_sodium_platform}"
        "-DLEEMEN_SODIUM_TOOLSET=${CMAKE_VS_PLATFORM_TOOLSET}"
        "-DLEEMEN_SODIUM_WINDOWS_SDK=${CMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION}"
        "-DLEEMEN_SODIUM_RUNTIME_PROPS=${leemen_sodium_root}/runtime-${leemen_sodium_config}.props"
    )
    set(leemen_sodium_library "libsodium.lib")
else()
    if(CMAKE_CROSSCOMPILING)
        message(FATAL_ERROR "Leemen libsodium autotools integration requires a native build.")
    endif()
    list(LENGTH CMAKE_OSX_ARCHITECTURES leemen_sodium_arch_count)
    if(leemen_sodium_arch_count GREATER 1)
        message(FATAL_ERROR "Build Leemen libsodium separately for each macOS architecture.")
    endif()
    if(NOT CMAKE_C_COMPILER_LOADED)
        enable_language(C)
    endif()
    find_program(leemen_sodium_make NAMES gmake make REQUIRED)
    find_package(Threads REQUIRED)
    list(APPEND leemen_sodium_build_args
        "-DLEEMEN_SODIUM_MAKE=${leemen_sodium_make}"
        "-DLEEMEN_SODIUM_CC=${CMAKE_C_COMPILER}"
        "-DLEEMEN_SODIUM_C_FLAGS=${CMAKE_C_FLAGS}"
        "-DLEEMEN_SODIUM_OSX_ARCH=${CMAKE_OSX_ARCHITECTURES}"
        "-DLEEMEN_SODIUM_OSX_SYSROOT=${CMAKE_OSX_SYSROOT}"
        "-DLEEMEN_SODIUM_OSX_DEPLOYMENT=${CMAKE_OSX_DEPLOYMENT_TARGET}"
    )
    set(leemen_sodium_library "install/lib/libsodium.a")
endif()

ExternalProject_Add(leemen_sodium_build
    SOURCE_DIR "${leemen_sodium_source_SOURCE_DIR}"
    PREFIX "${leemen_sodium_root}/steps"
    DOWNLOAD_COMMAND ""
    UPDATE_COMMAND ""
    PATCH_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND
        "${CMAKE_COMMAND}"
        "-DLEEMEN_SODIUM_SOURCE=${leemen_sodium_source_SOURCE_DIR}"
        "-DLEEMEN_SODIUM_ROOT=${leemen_sodium_root}"
        "-DLEEMEN_SODIUM_CONFIG=${leemen_sodium_config}"
        ${leemen_sodium_build_args}
        -P "${CMAKE_CURRENT_LIST_DIR}/leemen_sodium_build.cmake"
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS
        "${leemen_sodium_root}/${leemen_sodium_config}/${leemen_sodium_library}"
    LOG_BUILD TRUE
    LOG_OUTPUT_ON_FAILURE TRUE
)
ExternalProject_Add_StepDependencies(leemen_sodium_build build
    "${CMAKE_CURRENT_LIST_DIR}/leemen_sodium_build.cmake")
if(WIN32)
    ExternalProject_Add_StepDependencies(leemen_sodium_build build
        "${leemen_sodium_root}/runtime-${leemen_sodium_config}.props")
endif()

add_library(leemen_sodium STATIC IMPORTED GLOBAL)
add_library(leemen::sodium ALIAS leemen_sodium)
add_dependencies(leemen_sodium leemen_sodium_build)
set(leemen_sodium_configs Debug Release RelWithDebInfo MinSizeRel
    ${CMAKE_CONFIGURATION_TYPES} ${CMAKE_BUILD_TYPE})
list(REMOVE_DUPLICATES leemen_sodium_configs)
set_target_properties(leemen_sodium PROPERTIES
    IMPORTED_LOCATION "${leemen_sodium_root}/Debug/${leemen_sodium_library}"
    IMPORTED_CONFIGURATIONS "${leemen_sodium_configs}"
    INTERFACE_INCLUDE_DIRECTORIES
        "${leemen_sodium_root}/include;${leemen_sodium_source_SOURCE_DIR}/src/libsodium/include"
    INTERFACE_COMPILE_DEFINITIONS SODIUM_STATIC
)
foreach(leemen_sodium_build_config IN LISTS leemen_sodium_configs)
    string(TOUPPER "${leemen_sodium_build_config}" leemen_sodium_upper_config)
    set_property(TARGET leemen_sodium PROPERTY
        "IMPORTED_LOCATION_${leemen_sodium_upper_config}"
        "${leemen_sodium_root}/${leemen_sodium_build_config}/${leemen_sodium_library}"
    )
endforeach()
if(WIN32)
    target_link_libraries(leemen_sodium INTERFACE advapi32)
else()
    target_link_libraries(leemen_sodium INTERFACE Threads::Threads)
endif()
