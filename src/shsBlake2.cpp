#include "shsBlake2.hpp"
#include "Blake2/blake2.h"
#include <stdexcept>

struct shsBlake2::Impl {
    blake2b_state state;
};

shsBlake2::shsBlake2(size_t output_length) 
    : impl(std::make_unique<Impl>()), output_len(output_length) {
    if (output_length == 0 || output_length > MAX_OUTPUT_SIZE) {
        throw std::invalid_argument("Invalid output length");
    }
    if (blake2b_init(&impl->state, output_length) != 0) {
        throw std::runtime_error("Failed to initialize Blake2b");
    }
}

shsBlake2::shsBlake2(const void* key, size_t key_length, size_t output_length)
    : impl(std::make_unique<Impl>()), output_len(output_length) {
    if (output_length == 0 || output_length > MAX_OUTPUT_SIZE) {
        throw std::invalid_argument("Invalid output length");
    }
    if (key_length > MAX_KEY_SIZE) {
        throw std::invalid_argument("Key too long");
    }
    if (blake2b_init_key(&impl->state, output_length, key, key_length) != 0) {
        throw std::runtime_error("Failed to initialize Blake2b with key");
    }
}

shsBlake2::shsBlake2(const std::vector<uint8_t>& key, size_t output_length)
    : shsBlake2(key.data(), key.size(), output_length) {}

shsBlake2::shsBlake2(const std::array<uint8_t, SALT_SIZE>& salt,
                     const std::array<uint8_t, PERSONAL_SIZE>& personal,
                     size_t output_length)
    : impl(std::make_unique<Impl>()), output_len(output_length) {
    if (output_length == 0 || output_length > MAX_OUTPUT_SIZE) {
        throw std::invalid_argument("Invalid output length");
    }
    
    blake2b_param params = {0};
    params.digest_length = static_cast<uint8_t>(output_length);
    params.key_length = 0;
    params.fanout = 1;
    params.depth = 1;
    
    std::copy(salt.begin(), salt.end(), params.salt);
    std::copy(personal.begin(), personal.end(), params.personal);
    
    if (blake2b_init_param(&impl->state, &params) != 0) {
        throw std::runtime_error("Failed to initialize Blake2b with parameters");
    }
}

shsBlake2::~shsBlake2() = default;

void shsBlake2::update(const void* data, size_t length) {
    if (blake2b_update(&impl->state, data, length) != 0) {
        throw std::runtime_error("Failed to update Blake2b hash");
    }
}

void shsBlake2::update(const std::vector<uint8_t>& data) {
    update(data.data(), data.size());
}

void shsBlake2::update(const std::string& data) {
    update(data.data(), data.size());
}

std::vector<uint8_t> shsBlake2::finalize() {
    std::vector<uint8_t> result(output_len);
    if (blake2b_final(&impl->state, result.data(), output_len) != 0) {
        throw std::runtime_error("Failed to finalize Blake2b hash");
    }
    return result;
}

void shsBlake2::finalize(void* out, size_t outlen) {
    if (outlen != output_len) {
        throw std::invalid_argument("Output length mismatch");
    }
    if (blake2b_final(&impl->state, out, outlen) != 0) {
        throw std::runtime_error("Failed to finalize Blake2b hash");
    }
}


std::vector<uint8_t> shsBlake2::hash(const void* data, size_t length, size_t output_length) {
    shsBlake2 hasher(output_length);
    hasher.update(data, length);
    return hasher.finalize();
}

std::vector<uint8_t> shsBlake2::hash(const std::vector<uint8_t>& data, size_t output_length) {
    return hash(data.data(), data.size(), output_length);
}

std::vector<uint8_t> shsBlake2::hash(const std::string& data, size_t output_length) {
    return hash(data.data(), data.size(), output_length);
}

std::vector<uint8_t> shsBlake2::hash_keyed(const void* data, size_t length, 
                                          const void* key, size_t key_length,
                                          size_t output_length) {
    shsBlake2 hasher(key, key_length, output_length);
    hasher.update(data, length);
    return hasher.finalize();
}

std::vector<uint8_t> shsBlake2::hash_keyed(const std::vector<uint8_t>& data,
                                          const std::vector<uint8_t>& key,
                                          size_t output_length) {
    return hash_keyed(data.data(), data.size(), key.data(), key.size(), output_length);
}

std::vector<uint8_t> shsBlake2::hash_long(const void* data, size_t length, size_t output_length) {
    std::vector<uint8_t> result(output_length);
    if (blake2b_long(result.data(), output_length, data, length) != 0) {
        throw std::runtime_error("Failed to compute long Blake2b hash");
    }
    return result;
}

std::vector<uint8_t> shsBlake2::hash_long(const std::vector<uint8_t>& data, size_t output_length) {
    return hash_long(data.data(), data.size(), output_length);
}

std::vector<uint8_t> shsBlake2::hash_long(const std::string& data, size_t output_length) {
    return hash_long(data.data(), data.size(), output_length);
}