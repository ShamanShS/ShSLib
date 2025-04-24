#include <gtest/gtest.h>
#include "aes.hpp"
#include <vector>
#include <string>
#include <algorithm>
#include <chrono>
#include <iomanip>

using std::vector;
using std::string;

// Базовые unit-тесты
class AESTest : public ::testing::Test {
protected:
    AES aes;

    vector<unsigned char> key128 = vector<unsigned char>(16, 0x00);
    vector<unsigned char> key192 = vector<unsigned char>(24, 0x00);
    vector<unsigned char> key256 = vector<unsigned char>(32, 0x00);
    vector<unsigned char> iv = vector<unsigned char>(16, 0x01);
    
    vector<unsigned char> data16 = {'T', 'e', 's', 't', ' ', 'A', 'E', 'S', ' ', '1', '2', '8', '!', '!', '!', '!'};
    vector<unsigned char> emptyData = {};
    vector<unsigned char> maxData = vector<unsigned char>(1024 * 1024, 0xAA);

    void SetUp() override {
        std::fill(key128.begin(), key128.end(), 0x11);
        std::fill(key192.begin(), key192.end(), 0x22);
        std::fill(key256.begin(), key256.end(), 0x33);
        std::fill(iv.begin(), iv.end(), 0x44);
    }
};

// Unit-тесты
TEST_F(AESTest, EncryptDecryptECB_128) {
    auto encrypted = aes.EncryptECB(data16, key128);
    auto decrypted = aes.DecryptECB(encrypted, key128);
    ASSERT_EQ(decrypted, data16);
}

TEST_F(AESTest, EncryptDecryptECB_192) {
    auto encrypted = aes.EncryptECB(data16, key192);
    auto decrypted = aes.DecryptECB(encrypted, key192);
    ASSERT_EQ(decrypted, data16);
}

TEST_F(AESTest, EncryptDecryptECB_256) {
    auto encrypted = aes.EncryptECB(data16, key256);
    auto decrypted = aes.DecryptECB(encrypted, key256);
    ASSERT_EQ(decrypted, data16);
}

TEST_F(AESTest, EncryptDecryptCBC_128) {
    auto encrypted = aes.EncryptCBC(data16, key128, iv);
    auto decrypted = aes.DecryptCBC(encrypted, key128, iv);
    ASSERT_EQ(decrypted, data16);
}

TEST_F(AESTest, EncryptDecryptCBC_256) {
    auto encrypted = aes.EncryptCBC(data16, key256, iv);
    auto decrypted = aes.DecryptCBC(encrypted, key256, iv);
    ASSERT_EQ(decrypted, data16);
}

TEST_F(AESTest, CBC_IVChangesCiphertext) {
    auto iv2 = vector<unsigned char>(16, 0x55);
    auto cipher1 = aes.EncryptCBC(data16, key128, iv);
    auto cipher2 = aes.EncryptCBC(data16, key128, iv2);
    ASSERT_NE(cipher1, cipher2);
}

// Тесты для CFB режима
TEST_F(AESTest, EncryptDecryptCFB_128) {
    auto encrypted = aes.EncryptCFB(data16, key128, iv);
    auto decrypted = aes.DecryptCFB(encrypted, key128, iv);
    ASSERT_EQ(decrypted, data16);
}

TEST_F(AESTest, CFB_IVChangesCiphertext) {
    auto iv2 = vector<unsigned char>(16, 0x55);
    auto cipher1 = aes.EncryptCFB(data16, key128, iv);
    auto cipher2 = aes.EncryptCFB(data16, key128, iv2);
    ASSERT_NE(cipher1, cipher2);
}


TEST_F(AESTest, CBC_EmptyData) {
    auto encrypted = aes.EncryptCBC(emptyData, key128, iv);
    auto decrypted = aes.DecryptCBC(encrypted, key128, iv);
    ASSERT_EQ(decrypted, emptyData);
}

TEST_F(AESTest, CFB_EmptyData) {
    auto encrypted = aes.EncryptCFB(emptyData, key128, iv);
    auto decrypted = aes.DecryptCFB(encrypted, key128, iv);
    ASSERT_EQ(decrypted, emptyData);
}

TEST_F(AESTest, ECB_LargeData) {
    auto encrypted = aes.EncryptECB(maxData, key256);
    auto decrypted = aes.DecryptECB(encrypted, key256);
    ASSERT_EQ(decrypted, maxData);
}

TEST_F(AESTest, CBC_TamperedCiphertext) {
    auto encrypted = aes.EncryptCBC(data16, key128, iv);
    encrypted[5] ^= 0x01;
    auto decrypted = aes.DecryptCBC(encrypted, key128, iv);
    ASSERT_NE(decrypted, data16);
}

TEST_F(AESTest, CFB_TamperedCiphertext) {
    auto encrypted = aes.EncryptCFB(data16, key128, iv);
    encrypted[5] ^= 0x01;
    auto decrypted = aes.DecryptCFB(encrypted, key128, iv);
    ASSERT_NE(decrypted, data16);
}


TEST_F(AESTest, WrongKeyECB) {
    auto encrypted = aes.EncryptECB(data16, key128);
    vector<unsigned char> wrongKey(16, 0xFF);
    auto decrypted = aes.DecryptECB(encrypted, wrongKey);
    ASSERT_NE(decrypted, data16);
}

TEST_F(AESTest, WrongKeyCBC) {
    auto encrypted = aes.EncryptCBC(data16, key128, iv);
    vector<unsigned char> wrongKey(16, 0xFF);
    auto decrypted = aes.DecryptCBC(encrypted, wrongKey, iv);
    ASSERT_NE(decrypted, data16);
}


TEST_F(AESTest, ECB_Deterministic) {
    auto encrypted1 = aes.EncryptECB(data16, key128);
    auto encrypted2 = aes.EncryptECB(data16, key128);
    ASSERT_EQ(encrypted1, encrypted2);
}

TEST_F(AESTest, CBC_NonDeterministic) {
    auto encrypted1 = aes.EncryptCBC(data16, key128, iv);
    auto encrypted2 = aes.EncryptCBC(data16, key128, iv);
    ASSERT_EQ(encrypted1, encrypted2); 
    
    auto iv2 = vector<unsigned char>(16, 0x55);
    auto encrypted3 = aes.EncryptCBC(data16, key128, iv2);
    ASSERT_NE(encrypted1, encrypted3); 
}

// Тесты производительности
class AESPerformanceTest : public ::testing::Test {
protected:
    AES aes;
    vector<unsigned char> key128 = vector<unsigned char>(16, 0x11);
    vector<unsigned char> key256 = vector<unsigned char>(32, 0x33);
    vector<unsigned char> iv = vector<unsigned char>(16, 0x44);
    
    vector<unsigned char> data1K = vector<unsigned char>(1024, 0xAA);
    vector<unsigned char> data10K = vector<unsigned char>(10240, 0xBB);
    vector<unsigned char> data100K = vector<unsigned char>(102400, 0xCC);
    vector<unsigned char> data1M = vector<unsigned char>(1048576, 0xDD);
    vector<unsigned char> data10M = vector<unsigned char>(10485760, 0xEE);

    template<typename Func>
    void measure_performance(const string& test_name, Func func, const vector<unsigned char>& data) {
        // Warm-up
        for (int i = 0; i < 3; ++i) {
            func();
        }
        
        auto start = std::chrono::high_resolution_clock::now();
        
        const int runs = 10;
        for (int i = 0; i < runs; ++i) {
            func();
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double avg_time = duration / static_cast<double>(runs);
        double speed = (data.size() * runs) / (duration / 1000.0) / (1024 * 1024); // MB/s
        
        std::cout << std::fixed << std::setprecision(2);
        std::cout << "[PERF] " << test_name << " (" << data.size() / 1024 << " KB): "
                  << avg_time << " ms, " << speed << " MB/s" << std::endl;
    }
};

TEST_F(AESPerformanceTest, ECB_128_Performance) {
    std::cout << "\nECB 128-bit performance:\n";
    measure_performance("1K", [&]() {
        auto encrypted = aes.EncryptECB(data1K, key128);
        aes.DecryptECB(encrypted, key128);
    }, data1K);

    measure_performance("10K", [&]() {
        auto encrypted = aes.EncryptECB(data10K, key128);
        aes.DecryptECB(encrypted, key128);
    }, data10K);

    measure_performance("100K", [&]() {
        auto encrypted = aes.EncryptECB(data100K, key128);
        aes.DecryptECB(encrypted, key128);
    }, data100K);

    measure_performance("1M", [&]() {
        auto encrypted = aes.EncryptECB(data1M, key128);
        aes.DecryptECB(encrypted, key128);
    }, data1M);

    measure_performance("10M", [&]() {
        auto encrypted = aes.EncryptECB(data10M, key128);
        aes.DecryptECB(encrypted, key128);
    }, data10M);
}

TEST_F(AESPerformanceTest, CBC_128_Performance) {
    std::cout << "\nCBC 128-bit performance:\n";
    measure_performance("1K", [&]() {
        auto encrypted = aes.EncryptCBC(data1K, key128, iv);
        aes.DecryptCBC(encrypted, key128, iv);
    }, data1K);

    measure_performance("1M", [&]() {
        auto encrypted = aes.EncryptCBC(data1M, key128, iv);
        aes.DecryptCBC(encrypted, key128, iv);
    }, data1M);
}

TEST_F(AESPerformanceTest, CFB_128_Performance) {
    std::cout << "\nCFB 128-bit performance:\n";
    measure_performance("1K", [&]() {
        auto encrypted = aes.EncryptCFB(data1K, key128, iv);
        aes.DecryptCFB(encrypted, key128, iv);
    }, data1K);

    measure_performance("1M", [&]() {
        auto encrypted = aes.EncryptCFB(data1M, key128, iv);
        aes.DecryptCFB(encrypted, key128, iv);
    }, data1M);
}

TEST_F(AESPerformanceTest, CompareModes_Performance) {
    std::cout << "\nComparing encryption modes with 1MB data (128-bit key):\n";
    
    measure_performance("ECB", [&]() {
        auto encrypted = aes.EncryptECB(data1M, key128);
        aes.DecryptECB(encrypted, key128);
    }, data1M);
    
    measure_performance("CBC", [&]() {
        auto encrypted = aes.EncryptCBC(data1M, key128, iv);
        aes.DecryptCBC(encrypted, key128, iv);
    }, data1M);
    
    measure_performance("CFB", [&]() {
        auto encrypted = aes.EncryptCFB(data1M, key128, iv);
        aes.DecryptCFB(encrypted, key128, iv);
    }, data1M);
}

TEST_F(AESPerformanceTest, CompareKeySizes_Performance) {
    std::cout << "\nComparing key sizes with 1MB data (ECB mode):\n";
    
    measure_performance("128-bit", [&]() {
        auto encrypted = aes.EncryptECB(data1M, key128);
        aes.DecryptECB(encrypted, key128);
    }, data1M);
    
    measure_performance("256-bit", [&]() {
        auto encrypted = aes.EncryptECB(data1M, key256);
        aes.DecryptECB(encrypted, key256);
    }, data1M);
}
