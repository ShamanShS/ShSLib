#ifndef SHS_BLAKE2_HPP
#define SHS_BLAKE2_HPP

#include <array>
#include <vector>
#include <string>
#include <memory>

class shsBlake2 {
public:

    static constexpr size_t BLOCK_SIZE = 128;
    static constexpr size_t MAX_OUTPUT_SIZE = 64;
    static constexpr size_t MAX_KEY_SIZE = 64;
    static constexpr size_t SALT_SIZE = 16;
    static constexpr size_t PERSONAL_SIZE = 16;


    explicit shsBlake2(size_t output_length = MAX_OUTPUT_SIZE);
    shsBlake2(const void* key, size_t key_length, size_t output_length = MAX_OUTPUT_SIZE);
    shsBlake2(const std::vector<uint8_t>& key, size_t output_length = MAX_OUTPUT_SIZE);

    shsBlake2(const std::array<uint8_t, SALT_SIZE>& salt,
              const std::array<uint8_t, PERSONAL_SIZE>& personal,
              size_t output_length = MAX_OUTPUT_SIZE);
    
    ~shsBlake2();


    void update(const void* data, size_t length);
    void update(const std::vector<uint8_t>& data);
    void update(const std::string& data);


    std::vector<uint8_t> finalize();
    void finalize(void* out, size_t outlen);


    static std::vector<uint8_t> hash(const void* data, size_t length, 
                                    size_t output_length = MAX_OUTPUT_SIZE);
    static std::vector<uint8_t> hash(const std::vector<uint8_t>& data, 
                                    size_t output_length = MAX_OUTPUT_SIZE);
    static std::vector<uint8_t> hash(const std::string& data, 
                                    size_t output_length = MAX_OUTPUT_SIZE);
    

    static std::vector<uint8_t> hash_keyed(const void* data, size_t length, 
                                         const void* key, size_t key_length,
                                         size_t output_length = MAX_OUTPUT_SIZE);
    static std::vector<uint8_t> hash_keyed(const std::vector<uint8_t>& data,
                                         const std::vector<uint8_t>& key,
                                         size_t output_length = MAX_OUTPUT_SIZE);


    static std::vector<uint8_t> hash_long(const void* data, size_t length, 
                                         size_t output_length);
    static std::vector<uint8_t> hash_long(const std::vector<uint8_t>& data, 
                                         size_t output_length);
    static std::vector<uint8_t> hash_long(const std::string& data, 
                                         size_t output_length);


    shsBlake2(const shsBlake2&) = delete;
    shsBlake2& operator=(const shsBlake2&) = delete;

private:
    struct Impl;
    std::unique_ptr<Impl> impl;
    size_t output_len;
};

#endif // SHS_BLAKE2_HPP