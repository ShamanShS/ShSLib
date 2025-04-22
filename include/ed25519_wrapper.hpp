#pragma once

#include <vector>
#include <string>

namespace mylib::crypto::ed25519 {

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> create_keypair();  // pub, priv
std::vector<uint8_t> sign(const std::string& message, const std::vector<uint8_t>& pub, const std::vector<uint8_t>& priv);
bool verify(const std::string& message, const std::vector<uint8_t>& sig, const std::vector<uint8_t>& pub);

}
