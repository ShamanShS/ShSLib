#include <gtest/gtest.h>
#include "shsSHA512.hpp"
#include <vector>
#include <string>
#include <array>
#include <random>
#include <cstring>
#include <iomanip>
#include <functional>

using namespace std;

class SHA512Test : public ::testing::Test {
protected:
    void SetUp() override {
        // Тестовые данные
        test_string = "Hello, SHA-512!";
        test_vector = {'T', 'e', 's', 't', ' ', 'd', 'a', 't', 'a'};
        large_data = generateRandomData(1024 * 1024); // 1MB данных
        empty_data = {};
    }

    vector<uint8_t> generateRandomData(size_t length) {
        vector<uint8_t> data(length);
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<> dis(0, 255);

        generate(data.begin(), data.end(), [&]() { return static_cast<uint8_t>(dis(gen)); });
        return data;
    }

    string test_string;
    vector<uint8_t> test_vector;
    vector<uint8_t> large_data;
    vector<uint8_t> empty_data;
};

TEST_F(SHA512Test, ConstructionAndDestruction) {
    shsSHA512 hasher;
    SUCCEED(); 
}

TEST_F(SHA512Test, UpdateWithString) {
    shsSHA512 hasher;
    hasher.update(test_string);
    auto hash = hasher.finalize();
    EXPECT_FALSE(hash.empty());
}

TEST_F(SHA512Test, UpdateWithVector) {
    shsSHA512 hasher;
    hasher.update(test_vector);
    auto hash = hasher.finalize();
    EXPECT_FALSE(hash.empty());
}

TEST_F(SHA512Test, UpdateWithRawData) {
    shsSHA512 hasher;
    hasher.update(test_vector.data(), test_vector.size());
    auto hash = hasher.finalize();
    EXPECT_FALSE(hash.empty());
}

TEST_F(SHA512Test, ChunkedUpdate) {
    shsSHA512 hasher1;
    shsSHA512 hasher2;

    hasher1.update(large_data);
    auto hash1 = hasher1.finalize();

    const size_t chunk_size = 128;
    for (size_t i = 0; i < large_data.size(); i += chunk_size) {
        size_t end = min(i + chunk_size, large_data.size());
        hasher2.update(large_data.data() + i, end - i);
    }
    auto hash2 = hasher2.finalize();

    EXPECT_EQ(hash1, hash2);
}

TEST_F(SHA512Test, FinalizeReturnsCorrectSize) {
    shsSHA512 hasher;
    hasher.update(test_string);
    auto hash = hasher.finalize();
    EXPECT_EQ(hash.size(), 64);
}

TEST_F(SHA512Test, StaticHashString) {
    auto hash = shsSHA512::hash(test_string);
    EXPECT_EQ(hash.size(), 64);
}

TEST_F(SHA512Test, StaticHashVector) {
    auto hash = shsSHA512::hash(test_vector);
    EXPECT_EQ(hash.size(), 64);
}

TEST_F(SHA512Test, StaticHashRawData) {
    auto hash = shsSHA512::hash(test_vector.data(), test_vector.size());
    EXPECT_EQ(hash.size(), 64);
}


TEST_F(SHA512Test, EmptyInput) {
    shsSHA512 hasher;
    hasher.update(empty_data);
    auto hash1 = hasher.finalize();

    auto hash2 = shsSHA512::hash(empty_data);
    auto hash3 = shsSHA512::hash("");

    EXPECT_EQ(hash1, hash2);
    EXPECT_EQ(hash1, hash3);
}

TEST_F(SHA512Test, LargeInput) {
    auto hash = shsSHA512::hash(large_data);
    EXPECT_EQ(hash.size(), 64);
}

TEST_F(SHA512Test, DeterministicHashing) {
    auto hash1 = shsSHA512::hash(test_string);
    auto hash2 = shsSHA512::hash(test_string);
    EXPECT_EQ(hash1, hash2);

    shsSHA512 hasher1;
    hasher1.update(test_string);
    auto hash3 = hasher1.finalize();

    shsSHA512 hasher2;
    hasher2.update(test_string);
    auto hash4 = hasher2.finalize();

    EXPECT_EQ(hash1, hash3);
    EXPECT_EQ(hash3, hash4);
}

TEST_F(SHA512Test, KnownHashValues) {
    auto empty_hash = shsSHA512::hash("");
    array<uint8_t, 64> expected_empty = {
        0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 
        0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
        0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
        0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
        0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
        0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
        0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
        0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
    };
    EXPECT_EQ(empty_hash, expected_empty);

    auto abc_hash = shsSHA512::hash("abc");
    array<uint8_t, 64> expected_abc = {
        0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 
        0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
        0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
        0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
        0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
        0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
        0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
        0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
    };
    EXPECT_EQ(abc_hash, expected_abc);
}

TEST_F(SHA512Test, PerformanceTest) {
    const int iterations = 100;
    const size_t large_size = 1024 * 1024; // 1MB
    auto large_data = generateRandomData(large_size);

    auto start1 = chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        shsSHA512 hasher;
        hasher.update(large_data);
        hasher.finalize();
    }
    auto end1 = chrono::high_resolution_clock::now();

    auto start2 = chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        shsSHA512::hash(large_data);
    }
    auto end2 = chrono::high_resolution_clock::now();

    cout << "Performance results (avg per 1MB):\n";
    cout << "Incremental: " 
         << chrono::duration_cast<chrono::microseconds>(end1 - start1).count()/iterations 
         << " μs\n";
    cout << "Static: " 
         << chrono::duration_cast<chrono::microseconds>(end2 - start2).count()/iterations 
         << " μs\n";
}


TEST_F(SHA512Test, PerformanceTestDifferentSizes) {
    const int iterations = 10;
    const vector<size_t> test_sizes = {
        1024,       // 1 KB
        10 * 1024,   // 10 KB
        100 * 1024,  // 100 KB
        1024 * 1024, // 1 MB
        10 * 1024 * 1024 // 10 MB
    };

    cout << "\nSHA-512 Performance results (avg per operation):\n";
    cout << "-------------------------------------------------\n";
    cout << "| Size       | Time (μs)  | Speed (MB/s)        |\n";
    cout << "-------------------------------------------------\n";

    for (size_t size : test_sizes) {
        auto test_data = generateRandomData(size);

        // Прогрев
        shsSHA512::hash(test_data);

        auto start = chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i) {
            shsSHA512::hash(test_data);
        }
        auto end = chrono::high_resolution_clock::now();

        auto total_us = chrono::duration_cast<chrono::microseconds>(end - start).count();
        double avg_us = static_cast<double>(total_us) / iterations;
        double speed_mbs = (size / (1024.0 * 1024.0)) / (avg_us / 1000000.0);

        cout << "| " << setw(9) << size/1024 << " KB | "
             << setw(9) << static_cast<int>(avg_us) << " | "
             << setw(12) << fixed << setprecision(2) << speed_mbs << " MB/s |\n";
    }
    cout << "-------------------------------------------------\n";


    auto test_data = generateRandomData(1024 * 1024);
    cout << "\nComparing incremental vs static hashing for 1MB:\n";
    

    auto start_static = chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        shsSHA512::hash(test_data);
    }
    auto end_static = chrono::high_resolution_clock::now();
    

    auto start_inc = chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        shsSHA512 hasher;
        hasher.update(test_data);
        hasher.finalize();
    }
    auto end_inc = chrono::high_resolution_clock::now();
    
    cout << "Static:    " 
         << chrono::duration_cast<chrono::microseconds>(end_static - start_static).count()/iterations 
         << " μs\n";
    cout << "Incremental: " 
         << chrono::duration_cast<chrono::microseconds>(end_inc - start_inc).count()/iterations 
         << " μs\n";
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}