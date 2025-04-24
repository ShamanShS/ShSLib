#pragma once

#include <string>
#include <vector>
#include <random>
#include <stdexcept>
#include <sstream>
#include "argon2_wrapper.hpp"

namespace mylib::crypto {

class Argon2Hasher {
public:
    /**
     * Хэширует пароль + соль, возвращает "salt$hash"
     */
    static std::string hashPasswordWithSalt(
        const std::string& password,
        unsigned int t_cost = 3,
        unsigned int m_cost = 1 << 12,
        size_t salt_len = 16,
        size_t out_len = 32
    ) {
        auto salt = generateSaltHex(salt_len);
        auto hash = hashPasswordHex(password, salt, t_cost, m_cost, out_len);

        // Соединяем соль и хэш
        return salt + "$" + hash;
    }

    /**
     * Проверяет пароль по строке "salt$hash"
     */
    static bool verifyPassword(
        const std::string& password,
        const std::string& stored, 
        unsigned int t_cost = 3,
        unsigned int m_cost = 1 << 12,
        size_t out_len = 32
    ) {
        auto [salt, expected_hash] = splitSaltAndHash(stored);

        auto computed_hash = hashPasswordHex(password, salt, t_cost, m_cost, out_len);
        return constantTimeCompare(computed_hash, expected_hash);
    }

    static std::pair<std::string, std::string> splitSaltAndHash(const std::string& stored) {
        auto pos = stored.find('$');
        if (pos == std::string::npos) {
            throw std::invalid_argument("Invalid stored format: missing separator '$'");
        }
        std::string salt = stored.substr(0, pos);
        std::string hash = stored.substr(pos + 1);
        return {salt, hash};
    }

private:
    static std::vector<uint8_t> hashPassword(
        const std::string& password,
        const std::string& salt,
        unsigned int t_cost,
        unsigned int m_cost,
        size_t out_len
    ) {
        std::vector<uint8_t> hash(out_len);

        int result = mylib::crypto::argon2::hash_argon2i(
            hash.data(), hash.size(),
            password.data(), password.size(),
            salt.data(), salt.size(),
            t_cost, m_cost
        );

        if (result != 0) {
            throw std::runtime_error(
                mylib::crypto::argon2::ErrorMessage(result)
            );
        }

        return hash;
    }

    static std::string hashPasswordHex(
        const std::string& password,
        const std::string& salt,
        unsigned int t_cost,
        unsigned int m_cost,
        size_t out_len
    ) {
        auto hash_bytes = hashPassword(password, salt, t_cost, m_cost, out_len);
        return bytesToHex(hash_bytes);
    }

    static std::vector<uint8_t> generateSalt(size_t length) {
        std::random_device rd;
        std::mt19937 engine(rd());
        std::uniform_int_distribution<uint8_t> dist(0, 255);

        std::vector<uint8_t> salt(length);
        for (auto& byte : salt) {
            byte = dist(engine);
        }
        return salt;
    }

    static std::string generateSaltHex(size_t length) {
        auto salt_bytes = generateSalt(length);
        return bytesToHex(salt_bytes);
    }

    static std::string bytesToHex(const std::vector<uint8_t>& bytes) {
        static const char* hex_chars = "0123456789abcdef";
        std::string hex;
        hex.reserve(bytes.size() * 2);
        for (uint8_t byte : bytes) {
            hex.push_back(hex_chars[(byte >> 4) & 0x0F]);
            hex.push_back(hex_chars[byte & 0x0F]);
        }
        return hex;
    }

    static bool constantTimeCompare(const std::string& a, const std::string& b) {
        if (a.size() != b.size()) return false;
        uint8_t result = 0;
        for (size_t i = 0; i < a.size(); ++i) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }


};

} // namespace mylib::crypto
