#include "ed25519_wrapper.hpp"
#include "ed25519.h"

namespace mylib::crypto::ed25519 {

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> create_keypair() {
    std::vector<uint8_t> seed(32);
    ed25519_create_seed(seed.data());

    std::vector<uint8_t> pub(32), priv(64);
    ed25519_create_keypair(pub.data(), priv.data(), seed.data());

    return { pub, priv };
}

std::vector<uint8_t> sign(const std::string& message, const std::vector<uint8_t>& pub, const std::vector<uint8_t>& priv) {
    std::vector<uint8_t> sig(64);
    ed25519_sign(sig.data(),
                 reinterpret_cast<const unsigned char*>(message.data()),
                 message.size(),
                 pub.data(), priv.data());
    return sig;
}

bool verify(const std::string& message, const std::vector<uint8_t>& sig, const std::vector<uint8_t>& pub) {
    return ed25519_verify(sig.data(),
                          reinterpret_cast<const unsigned char*>(message.data()),
                          message.size(),
                          pub.data()) == 1;
}

}
