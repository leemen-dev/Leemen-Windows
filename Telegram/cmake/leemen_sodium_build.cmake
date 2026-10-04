cmake_minimum_required(VERSION 3.20)

foreach(leemen_required IN ITEMS SOURCE ROOT CONFIG)
    if(NOT LEEMEN_SODIUM_${leemen_required})
        message(FATAL_ERROR "Missing LEEMEN_SODIUM_${leemen_required}.")
    endif()
endforeach()

set(leemen_output "${LEEMEN_SODIUM_ROOT}/${LEEMEN_SODIUM_CONFIG}")
file(MAKE_DIRECTORY "${leemen_output}")

function(leemen_sodium_run)
    execute_process(
        COMMAND ${ARGV}
        WORKING_DIRECTORY "${leemen_output}"
        RESULT_VARIABLE leemen_result
    )
    if(NOT leemen_result EQUAL 0)
        message(FATAL_ERROR "Pinned libsodium build failed: ${leemen_result}")
    endif()
endfunction()

if(LEEMEN_SODIUM_MSBUILD)
    if(LEEMEN_SODIUM_CONFIG STREQUAL "Debug")
        set(leemen_configuration DebugLIB)
    else()
        set(leemen_configuration ReleaseLIB)
    endif()
    set(leemen_msbuild_args
        "${LEEMEN_SODIUM_SOURCE}/builds/msvc/vs2022/libsodium/libsodium.vcxproj"
        /nologo /m /t:Build
        "/p:Configuration=${leemen_configuration}"
        "/p:Platform=${LEEMEN_SODIUM_PLATFORM}"
        "/p:OutDir=${leemen_output}/"
        "/p:IntDir=${leemen_output}/obj/"
        "/p:ForceImportBeforeCppTargets=${LEEMEN_SODIUM_RUNTIME_PROPS}"
    )
    if(LEEMEN_SODIUM_TOOLSET)
        list(APPEND leemen_msbuild_args "/p:PlatformToolset=${LEEMEN_SODIUM_TOOLSET}")
    endif()
    if(LEEMEN_SODIUM_WINDOWS_SDK)
        list(APPEND leemen_msbuild_args
            "/p:WindowsTargetPlatformVersion=${LEEMEN_SODIUM_WINDOWS_SDK}")
    endif()
    leemen_sodium_run("${LEEMEN_SODIUM_MSBUILD}" ${leemen_msbuild_args})
else()
    if(NOT LEEMEN_SODIUM_MAKE OR NOT LEEMEN_SODIUM_CC)
        message(FATAL_ERROR "Native libsodium build requires a C compiler and make.")
    endif()
    if(LEEMEN_SODIUM_CONFIG STREQUAL "Debug")
        set(leemen_c_flags "-O0 -g")
    elseif(LEEMEN_SODIUM_CONFIG STREQUAL "RelWithDebInfo")
        set(leemen_c_flags "-O2 -g")
    elseif(LEEMEN_SODIUM_CONFIG STREQUAL "MinSizeRel")
        set(leemen_c_flags "-Os")
    else()
        set(leemen_c_flags "-O2")
    endif()
    string(APPEND leemen_c_flags " ${LEEMEN_SODIUM_C_FLAGS}")
    if(LEEMEN_SODIUM_OSX_ARCH)
        string(APPEND leemen_c_flags " -arch ${LEEMEN_SODIUM_OSX_ARCH}")
    endif()
    set(leemen_environment "CC=${LEEMEN_SODIUM_CC}" "CFLAGS=${leemen_c_flags}")
    if(LEEMEN_SODIUM_OSX_DEPLOYMENT)
        list(APPEND leemen_environment
            "MACOSX_DEPLOYMENT_TARGET=${LEEMEN_SODIUM_OSX_DEPLOYMENT}")
    endif()
    if(LEEMEN_SODIUM_OSX_SYSROOT)
        list(APPEND leemen_environment "SDKROOT=${LEEMEN_SODIUM_OSX_SYSROOT}")
    endif()
    leemen_sodium_run("${CMAKE_COMMAND}" -E env
        ${leemen_environment}
        "${LEEMEN_SODIUM_SOURCE}/configure"
        --disable-shared --enable-static --with-pic
        "--prefix=${leemen_output}/install"
    )
    leemen_sodium_run("${CMAKE_COMMAND}" -E env
        ${leemen_environment} "${LEEMEN_SODIUM_MAKE}" -j4)
    leemen_sodium_run("${CMAKE_COMMAND}" -E env
        ${leemen_environment} "${LEEMEN_SODIUM_MAKE}" install)
endif()
