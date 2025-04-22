cmake_minimum_required(VERSION 3.14)
project(ShSlibProject)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# === Опции сборки ===
option(BUILD_PYTHON_MODULE "Build Python bindings" ON)
option(BUILD_CPP_LIBRARY "Build C++ library" ON)

# === Общие настройки ===
include_directories(include)

# === Fetch pybind11 ===
include(FetchContent)
FetchContent_Declare(
    pybind11
    GIT_REPOSITORY https://github.com/pybind/pybind11.git
    GIT_TAG        v2.11.1
)
FetchContent_MakeAvailable(pybind11)

# === Сборка C++ библиотеки ===
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

        src/RSA/RSA.cpp
        src/RSA/utils.cpp
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

# === Сборка Python-модуля ===
if (BUILD_PYTHON_MODULE)
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
