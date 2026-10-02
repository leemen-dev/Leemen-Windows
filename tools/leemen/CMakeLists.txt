cmake_minimum_required(VERSION 3.20)

project(LeemenCoreTests LANGUAGES CXX)

enable_testing()
find_package(OpenSSL REQUIRED COMPONENTS Crypto)
include("${CMAKE_CURRENT_LIST_DIR}/../../Telegram/cmake/leemen_sodium.cmake")

set(leemen_source_root "${CMAKE_CURRENT_LIST_DIR}/../../Telegram/SourceFiles")

add_executable(leemen_private_space_tests
    "${leemen_source_root}/leemen/private_space_state.cpp"
    "${leemen_source_root}/test/leemen/private_space_state_tests.cpp"
)
add_executable(leemen_local_pin_tests
    "${leemen_source_root}/leemen/local_pin.cpp"
    "${leemen_source_root}/test/leemen/local_pin_tests.cpp"
)
target_link_libraries(leemen_local_pin_tests PRIVATE OpenSSL::Crypto)

add_executable(leemen_sync_identifier_tests
    "${leemen_source_root}/leemen/sync_identifiers.cpp"
    "${leemen_source_root}/test/leemen/sync_identifiers_tests.cpp"
)

add_executable(leemen_private_drafts_tests
    "${leemen_source_root}/test/leemen/private_drafts_tests.cpp"
)

add_executable(leemen_sync_blob_tests
    "${leemen_source_root}/leemen/sync_blob.cpp"
    "${leemen_source_root}/leemen/sync_identifiers.cpp"
    "${leemen_source_root}/test/leemen/sync_blob_tests.cpp"
)
add_executable(leemen_sync_coordinator_tests
    "${leemen_source_root}/leemen/sync_blob.cpp"
    "${leemen_source_root}/leemen/sync_identifiers.cpp"
    "${leemen_source_root}/leemen/sync_coordinator.cpp"
    "${leemen_source_root}/test/leemen/sync_coordinator_tests.cpp"
)
add_executable(leemen_sync_local_intents_tests
    "${leemen_source_root}/leemen/sync_blob.cpp"
    "${leemen_source_root}/leemen/sync_identifiers.cpp"
    "${leemen_source_root}/test/leemen/sync_local_intents_tests.cpp"
)
add_executable(leemen_sync_crypto_tests
    "${leemen_source_root}/leemen/sync_crypto.cpp"
    "${leemen_source_root}/test/leemen/sync_crypto_tests.cpp"
)
target_link_libraries(leemen_sync_crypto_tests PRIVATE OpenSSL::Crypto leemen::sodium)

add_executable(leemen_sync_backend_tests
    "${leemen_source_root}/leemen/sync_backend.cpp"
    "${leemen_source_root}/leemen/sync_blob.cpp"
    "${leemen_source_root}/leemen/sync_identifiers.cpp"
    "${leemen_source_root}/leemen/sync_crypto.cpp"
    "${leemen_source_root}/test/leemen/sync_backend_tests.cpp"
)
target_link_libraries(leemen_sync_backend_tests PRIVATE OpenSSL::Crypto leemen::sodium)
add_executable(leemen_security_policy_tests
    "${leemen_source_root}/leemen/security_policy.cpp"
    "${leemen_source_root}/test/leemen/security_policy_tests.cpp"
)
add_executable(leemen_max_privacy_tests
    "${leemen_source_root}/leemen/max_privacy.cpp"
    "${leemen_source_root}/leemen/sync_crypto.cpp"
    "${leemen_source_root}/test/leemen/max_privacy_tests.cpp"
)
target_link_libraries(leemen_max_privacy_tests PRIVATE OpenSSL::Crypto leemen::sodium)

foreach(leemen_test IN ITEMS
        leemen_private_space_tests
        leemen_local_pin_tests
        leemen_sync_identifier_tests
        leemen_private_drafts_tests
        leemen_sync_blob_tests
        leemen_sync_coordinator_tests
        leemen_sync_local_intents_tests
        leemen_security_policy_tests
        leemen_max_privacy_tests
        leemen_sync_crypto_tests
        leemen_sync_backend_tests)
    target_include_directories(${leemen_test} PRIVATE "${leemen_source_root}")
    target_compile_features(${leemen_test} PRIVATE cxx_std_20)
    set_target_properties(${leemen_test} PROPERTIES CXX_EXTENSIONS OFF)
    if(MSVC)
        target_compile_options(${leemen_test} PRIVATE /W4 /WX /permissive- /utf-8)
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(${leemen_test} PRIVATE
            -Wall -Wextra -Werror -pedantic
        )
    endif()
    add_test(NAME ${leemen_test} COMMAND ${leemen_test})
    set_tests_properties(${leemen_test} PROPERTIES TIMEOUT 120)
endforeach()
