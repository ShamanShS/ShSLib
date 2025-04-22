#include "../include/argon2_wrapper.hpp"

// Подключаем оригинальный код
#include "Argon2/argon2.h"

namespace mylib::crypto::argon2 {

// Объявляем структуру, которую мы спрятали в .hpp
using ::Argon2_Context;

// Функции хэширования
int hash_argon2i(void* out, size_t outlen,
                 const void* in, size_t inlen,
                 const void* salt, size_t saltlen,
                 unsigned int t_cost, unsigned int m_cost) {
    return ::hash_argon2i(out, outlen, in, inlen, salt, saltlen, t_cost, m_cost);
}

int hash_argon2d(void* out, size_t outlen,
                 const void* in, size_t inlen,
                 const void* salt, size_t saltlen,
                 unsigned int t_cost, unsigned int m_cost) {
    return ::hash_argon2d(out, outlen, in, inlen, salt, saltlen, t_cost, m_cost);
}

// Работа с контекстом
int Argon2i(Argon2_Context* context) {
    return ::Argon2i(context);
}

int Argon2d(Argon2_Context* context) {
    return ::Argon2d(context);
}

int Argon2id(Argon2_Context* context) {
    return ::Argon2id(context);
}

int Argon2ds(Argon2_Context* context) {
    return ::Argon2ds(context);
}

// Ошибки
const char* ErrorMessage(int error_code) {
    return ::ErrorMessage(error_code);
}

// Безопасная очистка памяти
void secure_wipe_memory(void* v, size_t n) {
    ::secure_wipe_memory(v, n);
}

} // namespace mylib::crypto::argon2
