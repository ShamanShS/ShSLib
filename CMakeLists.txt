cmake_minimum_required(VERSION 3.14)
project(ShSlibProject)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


option(BUILD_PYTHON_MODULE "Build Python bindings" ON)
option(BUILD_CPP_LIBRARY "Build C++ library" ON)
option(ENABLE_COVERAGE "Enable code coverage reporting" OFF)  # Новая опция для покрытия


include_directories(include)


if(ENABLE_COVERAGE)
    message(STATUS "Code coverage enabled")
    add_compile_options(-fprofile-arcs -ftest-coverage)
    add_link_options(--coverage)
    

    find_program(LCOV_PATH lcov)
    find_program(GENHTML_PATH genhtml)
    find_program(GCOVR_PATH gcovr)
endif()


include(FetchContent)


if (BUILD_CPP_LIBRARY)
    add_library(ShSlib SHARED
        src/aes.cpp
        src/myFunc.cpp
        src/argon2_wrapper.cpp
        src/Argon2/argon2-core.cpp
        src/Argon2/argon2-opt-core.cpp
        src/Argon2/argon2.cpp
        src/Argon2/kat.cpp
        src/Blake2/blake2b.c

        src/ed25519/src/add_scalar.c
        src/ed25519/src/fe.c
        src/ed25519/src/ge.c
        src/ed25519/src/key_exchange.c
        src/ed25519/src/keypair.c
        src/ed25519/src/sc.c
        src/ed25519/src/seed.c
        src/ed25519/src/sha512.c
        src/ed25519/src/sign.c
        src/ed25519/src/verify.c
        src/ed25519_wrapper.cpp

        src/shsSHA512.cpp
        src/shsBlake2.cpp
    )

    target_include_directories(ShSlib
        PUBLIC
            include
        PRIVATE
            src/Argon2
            src/Blake2
            src/ed25519/include
            src/RSA
    )
endif()


if (BUILD_PYTHON_MODULE)
    FetchContent_Declare(
        pybind11
        GIT_REPOSITORY https://github.com/pybind/pybind11.git
        GIT_TAG        v2.11.1
    )
    FetchContent_MakeAvailable(pybind11)
    add_library(ShSlibPy MODULE
        py_wrapper.cpp
        src/aes.cpp
        src/myFunc.cpp
        src/argon2_wrapper.cpp
        src/Argon2/argon2-core.cpp
        src/Argon2/argon2-opt-core.cpp
        src/Argon2/argon2.cpp
        src/Argon2/kat.cpp
        src/Blake2/blake2b.c

        src/ed25519/src/add_scalar.c
        src/ed25519/src/fe.c
        src/ed25519/src/ge.c
        src/ed25519/src/key_exchange.c
        src/ed25519/src/keypair.c
        src/ed25519/src/sc.c
        src/ed25519/src/seed.c
        src/ed25519/src/sha512.c
        src/ed25519/src/sign.c
        src/ed25519/src/verify.c
        src/ed25519_wrapper.cpp

        src/shsSHA512.cpp
        src/shsBlake2.cpp
    )

    set_target_properties(ShSlibPy PROPERTIES PREFIX "")
    if(WIN32)
        set_target_properties(ShSlibPy PROPERTIES SUFFIX ".pyd")
    endif()

    target_include_directories(ShSlibPy PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ed25519/include
    )

    target_link_libraries(ShSlibPy PRIVATE
        pybind11::module
        pybind11::headers
    )

    find_program(PYBIND11_STUBGEN pybind11-stubgen)
    if (PYBIND11_STUBGEN)
        add_custom_command(TARGET ShSlibPy POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E env
                PYTHONPATH=$<TARGET_FILE_DIR:ShSlibPy>
                ${PYBIND11_STUBGEN} ShSlibPy --output-dir=${CMAKE_CURRENT_BINARY_DIR}
            COMMENT "Generating .pyi stub with pybind11-stubgen..."
        )
    else()
        message(WARNING "pybind11-stubgen not found! No .pyi will be generated.")
    endif()
endif()


include(FetchContent)

FetchContent_Declare(
    googletest
    GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_TAG v1.16.0
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()


add_executable(test_aes tests/test_aes.cpp)
target_include_directories(test_aes PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(test_aes PRIVATE ShSlib gtest gtest_main)
add_test(NAME AES_Tests COMMAND test_aes)


add_executable(test_argon2 tests/test_argon2.cpp)
target_include_directories(test_argon2 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Argon2
)
target_link_libraries(test_argon2 PRIVATE ShSlib gtest gtest_main)
add_test(NAME Argon2_Tests COMMAND test_argon2)



add_executable(test_ed25519 tests/test_ed25519.cpp)
target_include_directories(test_ed25519 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/ed25519/include
)
target_link_libraries(test_ed25519 PRIVATE ShSlib gtest gtest_main)
add_test(NAME Ed25519_Tests COMMAND test_ed25519)



add_executable(test_blake2 tests/test_blake2b.cpp)
target_include_directories(test_blake2 PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/Blake2
 )
target_link_libraries(test_blake2 PRIVATE ShSlib gtest gtest_main)
add_test(NAME Blake2_Tests COMMAND test_blake2)



add_executable(test_sha512 tests/test_sha512.cpp)
target_include_directories(test_sha512 PRIVATE
 ${CMAKE_CURRENT_SOURCE_DIR}/include
 ${CMAKE_CURRENT_SOURCE_DIR}/src/ed25519/include
 )
target_link_libraries(test_sha512 PRIVATE ShSlib gtest gtest_main)
add_test(NAME SHA512_Tests COMMAND test_sha512)


if(ENABLE_COVERAGE)
    if(LCOV_PATH AND GENHTML_PATH)
        add_custom_target(coverage
            COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
            COMMAND ${LCOV_PATH} --capture --directory . --output-file coverage.info
            COMMAND ${LCOV_PATH} --remove coverage.info '*/tests/*' '*/usr/include/*' '*/pybind11/*' --output-file coverage.filtered.info
            COMMAND ${GENHTML_PATH} coverage.filtered.info --output-directory ${CMAKE_BINARY_DIR}/coverage_report
            COMMAND ${CMAKE_COMMAND} -E remove coverage.info coverage.filtered.info
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMENT "Generating code coverage report"
        )
    else()
        message(WARNING "lcov/genhtml not found! Cannot generate HTML coverage report")
    endif()

    if(GCOVR_PATH)
        add_custom_target(coverage-xml
            COMMAND ${GCOVR_PATH} --xml-pretty --exclude-unreachable-branches --exclude-throw-branches -o coverage.xml
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMENT "Generating XML coverage report"
        )
    else()
        message(WARNING "gcovr not found! Cannot generate XML coverage report")
    endif()
endif()