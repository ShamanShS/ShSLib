#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "include/aes.hpp"
#include "include/myFunc.hpp"
#include "include/argon2_wrapper.hpp"
#include "include/Argon2Hasher.hpp"
#include "ed25519_wrapper.hpp"

namespace py = pybind11;

void bind_aes(py::module_& m);
void bind_argon2(py::module_& m);
void bind_ed25519(py::module_& m);


PYBIND11_MODULE(ShSlibPy, m) {
    m.doc() = "Python bindings for AES, Argon2 and Ed25519 cryptographic operations";

    m.def("hi", 
        []() {
            h();  // Вызываем функцию из myfunc.h
            return "Function h() was called";
        },
        "Call C++ function h() from myfunc.h\n"
        "Returns:\n"
        "    Status message as string");

    bind_aes(m);
    bind_argon2(m);
    bind_ed25519(m);

}


void bind_ed25519(py::module_& m) {
    m.def("ed25519_create_keypair", []() {
        auto [pub, priv] = mylib::crypto::ed25519::create_keypair();
        return py::make_tuple(pub, priv);
    }, "Generate Ed25519 public and private key pair");

    m.def("ed25519_sign", &mylib::crypto::ed25519::sign,
          py::arg("message"), py::arg("public_key"), py::arg("private_key"),
          "Sign a message using Ed25519");

    m.def("ed25519_verify", &mylib::crypto::ed25519::verify,
          py::arg("message"), py::arg("signature"), py::arg("public_key"),
          "Verify Ed25519 signature");
}

void bind_aes(py::module_& m) {
    py::enum_<AESKeyLength>(m, "AESKeyLength")
        .value("AES_128", AESKeyLength::AES_128, "128-bit AES encryption")
        .value("AES_192", AESKeyLength::AES_192, "192-bit AES encryption")
        .value("AES_256", AESKeyLength::AES_256, "256-bit AES encryption");

    py::class_<AES>(m, "AES")
        .def(py::init<AESKeyLength>(), 
             py::arg("key_length"),
             "Initialize AES with specified key length\n"
             "Args:\n"
             "    key_length: AESKeyLength enum value (AES_128, AES_192 or AES_256)")

        // ECB mode
        .def("encrypt_ecb", 
             static_cast<std::vector<unsigned char> (AES::*)(std::vector<unsigned char>, std::vector<unsigned char>)>(
                 &AES::EncryptECB),
             py::arg("plaintext"),
             py::arg("key"),
             "Encrypt data in ECB mode\n"
             "Args:\n"
             "    plaintext: bytes-like object (length must be multiple of 16)\n"
             "    key: encryption key (16, 24 or 32 bytes)\n"
             "Returns:\n"
             "    Encrypted data as bytes")

        .def("decrypt_ecb",
             static_cast<std::vector<unsigned char> (AES::*)(std::vector<unsigned char>, std::vector<unsigned char>)>(
                 &AES::DecryptECB),
             py::arg("ciphertext"),
             py::arg("key"),
             "Decrypt data in ECB mode\n"
             "Args:\n"
             "    ciphertext: bytes-like object to decrypt\n"
             "    key: decryption key (same as encryption key)\n"
             "Returns:\n"
             "    Decrypted data as bytes")

        // CBC mode
        .def("encrypt_cbc",
             static_cast<std::vector<unsigned char> (AES::*)(std::vector<unsigned char>, std::vector<unsigned char>, std::vector<unsigned char>)>(
                 &AES::EncryptCBC),
             py::arg("plaintext"),
             py::arg("key"),
             py::arg("iv"),
             "Encrypt data in CBC mode\n"
             "Args:\n"
             "    plaintext: bytes-like object to encrypt\n"
             "    key: encryption key (16, 24 or 32 bytes)\n"
             "    iv: initialization vector (16 bytes)\n"
             "Returns:\n"
             "    Encrypted data as bytes")

        .def("decrypt_cbc",
             static_cast<std::vector<unsigned char> (AES::*)(std::vector<unsigned char>, std::vector<unsigned char>, std::vector<unsigned char>)>(
                 &AES::DecryptCBC),
             py::arg("ciphertext"),
             py::arg("key"),
             py::arg("iv"),
             "Decrypt data in CBC mode\n"
             "Args:\n"
             "    ciphertext: bytes-like object to decrypt\n"
             "    key: decryption key\n"
             "    iv: initialization vector used for encryption\n"
             "Returns:\n"
             "    Decrypted data as bytes")

        // CFB mode
        .def("encrypt_cfb",
             static_cast<std::vector<unsigned char> (AES::*)(std::vector<unsigned char>, std::vector<unsigned char>, std::vector<unsigned char>)>(
                 &AES::EncryptCFB),
             py::arg("plaintext"),
             py::arg("key"),
             py::arg("iv"),
             "Encrypt data in CFB mode\n"
             "Args:\n"
             "    plaintext: bytes-like object to encrypt\n"
             "    key: encryption key (16, 24 or 32 bytes)\n"
             "    iv: initialization vector (16 bytes)\n"
             "Returns:\n"
             "    Encrypted data as bytes")

        .def("decrypt_cfb",
             static_cast<std::vector<unsigned char> (AES::*)(std::vector<unsigned char>, std::vector<unsigned char>, std::vector<unsigned char>)>(
                 &AES::DecryptCFB),
             py::arg("ciphertext"),
             py::arg("key"),
             py::arg("iv"),
             "Decrypt data in CFB mode\n"
             "Args:\n"
             "    ciphertext: bytes-like object to decrypt\n"
             "    key: decryption key\n"
             "    iv: initialization vector used for encryption\n"
             "Returns:\n"
             "    Decrypted data as bytes");

}

void bind_argon2(py::module_& m) {
    py::class_<mylib::crypto::Argon2Hasher>(m, "Argon2Hasher")
        .def_static("hashPasswordWithSalt",
             &mylib::crypto::Argon2Hasher::hashPasswordWithSalt,
             py::arg("password"),
             py::arg("t_cost") = 3,
             py::arg("m_cost") = 1 << 12,
             py::arg("salt_len") = 16,
             py::arg("out_len") = 32,
             "Hash password with salt\n"
             "Args:\n"
             "    password: password to hash\n"
             "    t_cost: time cost (default: 3)\n"
             "    m_cost: memory cost (default: 1 << 12)\n"
             "    salt_len: length of the salt (default: 16)\n"
             "    out_len: length of the output hash (default: 32)\n"
             "Returns:\n"
             "    Salt and hash as string in format 'salt$hash'")

        .def_static("verifyPassword",
             &mylib::crypto::Argon2Hasher::verifyPassword,
             py::arg("password"),
             py::arg("stored"),
             py::arg("t_cost") = 3,
             py::arg("m_cost") = 1 << 12,
             py::arg("out_len") = 32,
             "Verify password against stored hash\n"
             "Args:\n"
             "    password: password to verify\n"
             "    stored: stored hash in format 'salt$hash'\n"
             "    t_cost: time cost (default: 3)\n"
             "    m_cost: memory cost (default: 1 << 12)\n"
             "    out_len: length of the output hash (default: 32)\n"
             "Returns:\n"
             "    True if password matches, False otherwise");
}