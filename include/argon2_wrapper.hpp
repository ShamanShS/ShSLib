#pragma once

#include <cstddef>
#include <cstdint>


extern "C" {
    struct Argon2_Context;
}

namespace mylib::crypto::argon2 {

// Использовать оригинальную структуру
using ::Argon2_Context;

// Основные функции хэширования
int hash_argon2i(void* out, size_t outlen,
                 const void* in, size_t inlen,
                 const void* salt, size_t saltlen,
                 unsigned int t_cost, unsigned int m_cost);

int hash_argon2d(void* out, size_t outlen,
                 const void* in, size_t inlen,
                 const void* salt, size_t saltlen,
                 unsigned int t_cost, unsigned int m_cost);

// Работа с контекстом
int Argon2i(Argon2_Context* context);
int Argon2d(Argon2_Context* context);
int Argon2id(Argon2_Context* context);
int Argon2ds(Argon2_Context* context);

// Вспомогательные функции
const char* ErrorMessage(int error_code);
void secure_wipe_memory(void* v, size_t n);

} // namespace mylib::crypto::argon2
