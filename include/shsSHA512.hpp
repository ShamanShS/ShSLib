#ifndef SHS_SHA512_HPP
#define SHS_SHA512_HPP

#include <string>
#include <vector>
#include <array>

class shsSHA512 {
public:
    shsSHA512();
    ~shsSHA512();


    void update(const std::vector<uint8_t>& data);
    void update(const std::string& data);
    void update(const uint8_t* data, size_t length);

    std::array<uint8_t, 64> finalize();  


    static std::array<uint8_t, 64> hash(const std::vector<uint8_t>& data);
    static std::array<uint8_t, 64> hash(const std::string& data);
    static std::array<uint8_t, 64> hash(const uint8_t* data, size_t length);


    shsSHA512(const shsSHA512&) = delete;
    shsSHA512& operator=(const shsSHA512&) = delete;

private:
    struct Impl;
    Impl* impl;
};

#endif // SHS_SHA512_HPP