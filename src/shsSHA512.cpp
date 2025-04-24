#include "shsSHA512.hpp"
#include "sha512.h"

struct shsSHA512::Impl {
    sha512_context context;
};

shsSHA512::shsSHA512() : impl(new Impl) {
    sha512_init(&impl->context);
}

shsSHA512::~shsSHA512() {
    delete impl;
}

void shsSHA512::update(const std::vector<uint8_t>& data) {
    sha512_update(&impl->context, data.data(), data.size());
}

void shsSHA512::update(const std::string& data) {
    sha512_update(&impl->context, 
                 reinterpret_cast<const unsigned char*>(data.data()), 
                 data.size());
}

void shsSHA512::update(const uint8_t* data, size_t length) {
    sha512_update(&impl->context, data, length);
}

std::array<uint8_t, 64> shsSHA512::finalize() {
    std::array<uint8_t, 64> result;
    sha512_final(&impl->context, result.data());
    return result;
}

std::array<uint8_t, 64> shsSHA512::hash(const std::vector<uint8_t>& data) {
    shsSHA512 hasher;
    hasher.update(data);
    return hasher.finalize();
}

std::array<uint8_t, 64> shsSHA512::hash(const std::string& data) {
    shsSHA512 hasher;
    hasher.update(data);
    return hasher.finalize();
}

std::array<uint8_t, 64> shsSHA512::hash(const uint8_t* data, size_t length) {
    shsSHA512 hasher;
    hasher.update(data, length);
    return hasher.finalize();
}