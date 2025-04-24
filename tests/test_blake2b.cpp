#include <gtest/gtest.h>
#include "shsBlake2.hpp"
#include <vector>
#include <string>
#include <array>
#include <random>
#include <cstring>
#include <iomanip>
#include <functional>

using namespace std;

class Blake2Test : public ::testing::Test {
protected:
    void SetUp() override {
        // Генерация тестовых данных
        default_data = "Test message for BLAKE2 hashing";
        random_data = generateRandomData(1024); // 1KB случайных данных
    }

    vector<uint8_t> generateRandomData(size_t length) {
        vector<uint8_t> data(length);
        random_device rd;
        mt19937 gen(rd());
        uniform_int_distribution<> dis(0, 255);

        for (auto& byte : data) {
            byte = static_cast<uint8_t>(dis(gen));
        }
        return data;
    }

    string default_data;
    vector<uint8_t> random_data;
    const array<uint8_t, 16> test_salt = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    const array<uint8_t, 16> test_personal = {16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1};
};

TEST_F(Blake2Test, DefaultConstructor) {
    shsBlake2 hasher;
    hasher.update(default_data);
    auto hash = hasher.finalize();
    EXPECT_EQ(hash.size(), shsBlake2::MAX_OUTPUT_SIZE);
}

TEST_F(Blake2Test, KeyedConstructor) {
    vector<uint8_t> key = {1,2,3,4,5};
    shsBlake2 hasher(key.data(), key.size());
    hasher.update(default_data);
    auto hash = hasher.finalize();
    EXPECT_EQ(hash.size(), shsBlake2::MAX_OUTPUT_SIZE);
}

TEST_F(Blake2Test, ParameterizedConstructor) {
    shsBlake2 hasher(test_salt, test_personal);
    hasher.update(default_data);
    auto hash = hasher.finalize();
    EXPECT_EQ(hash.size(), shsBlake2::MAX_OUTPUT_SIZE);
}

TEST_F(Blake2Test, UpdateMethods) {
    shsBlake2 hasher;
    
    hasher.update(default_data.data(), default_data.size());
    hasher.update(vector<uint8_t>(default_data.begin(), default_data.end()));
    hasher.update(default_data);
    
    auto hash = hasher.finalize();
    EXPECT_EQ(hash.size(), shsBlake2::MAX_OUTPUT_SIZE);
}

TEST_F(Blake2Test, ChunkedUpdate) {
    shsBlake2 hasher1;
    shsBlake2 hasher2;
    
    hasher1.update(random_data);
    auto hash1 = hasher1.finalize();
    
    size_t chunk_size = 128;
    for (size_t i = 0; i < random_data.size(); i += chunk_size) {
        size_t end = min(i + chunk_size, random_data.size());
        hasher2.update(random_data.data() + i, end - i);
    }
    auto hash2 = hasher2.finalize();
    
    EXPECT_EQ(hash1, hash2);
}


TEST_F(Blake2Test, StaticHashMethods) {
    auto hash1 = shsBlake2::hash(default_data.data(), default_data.size());
    auto hash2 = shsBlake2::hash(vector<uint8_t>(default_data.begin(), default_data.end()));
    auto hash3 = shsBlake2::hash(default_data);
    
    EXPECT_EQ(hash1, hash2);
    EXPECT_EQ(hash1, hash3);
    EXPECT_EQ(hash1.size(), shsBlake2::MAX_OUTPUT_SIZE);
}

TEST_F(Blake2Test, StaticHashCustomLength) {
    size_t custom_length = 32;
    auto hash = shsBlake2::hash(default_data, custom_length);
    EXPECT_EQ(hash.size(), custom_length);
}

TEST_F(Blake2Test, KeyedHashing) {
    vector<uint8_t> key = {1,2,3,4,5};
    
    auto hash1 = shsBlake2::hash_keyed(default_data.data(), default_data.size(), 
                                     key.data(), key.size());
    auto hash2 = shsBlake2::hash_keyed(vector<uint8_t>(default_data.begin(), default_data.end()),
                                     key);
    
    EXPECT_EQ(hash1, hash2);
    EXPECT_NE(hash1, shsBlake2::hash(default_data)); // Должно отличаться от обычного хеша
}



TEST_F(Blake2Test, EmptyInput) {
    string empty;
    auto hash = shsBlake2::hash(empty);
    EXPECT_EQ(hash.size(), shsBlake2::MAX_OUTPUT_SIZE);
    
    vector<uint8_t> empty_vec;
    auto hash2 = shsBlake2::hash(empty_vec);
    EXPECT_EQ(hash, hash2);
}

TEST_F(Blake2Test, MaxKeySize) {
    vector<uint8_t> max_key(shsBlake2::MAX_KEY_SIZE, 0xAA);
    shsBlake2 hasher(max_key.data(), max_key.size());
    hasher.update(default_data);
    auto hash = hasher.finalize();
    EXPECT_EQ(hash.size(), shsBlake2::MAX_OUTPUT_SIZE);
}

TEST_F(Blake2Test, InvalidOutputLength) {
    EXPECT_THROW(shsBlake2 hasher(0), invalid_argument);
    EXPECT_THROW(shsBlake2 hasher(shsBlake2::MAX_OUTPUT_SIZE + 1), invalid_argument);
    
    EXPECT_THROW(shsBlake2::hash(default_data, 0), invalid_argument);
    EXPECT_THROW(shsBlake2::hash(default_data, shsBlake2::MAX_OUTPUT_SIZE + 1), invalid_argument);
}

TEST_F(Blake2Test, DeterministicHashing) {
    auto hash1 = shsBlake2::hash(default_data);
    auto hash2 = shsBlake2::hash(default_data);
    EXPECT_EQ(hash1, hash2);
    
    shsBlake2 hasher1;
    hasher1.update(default_data);
    auto hash3 = hasher1.finalize();
    
    shsBlake2 hasher2;
    hasher2.update(default_data);
    auto hash4 = hasher2.finalize();
    
    EXPECT_EQ(hash1, hash3);
    EXPECT_EQ(hash3, hash4);
}

TEST_F(Blake2Test, PerformanceTest) {
    const int iterations = 1000;
    const size_t large_size = 1024 * 1024; // 1MB
    auto large_data = generateRandomData(large_size);
    
    // Тестируем скорость статического хеширования
    auto start1 = chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        shsBlake2::hash(large_data);
    }
    auto end1 = chrono::high_resolution_clock::now();
    
    cout << "Performance results:\n";
    cout << "Static hash: " 
         << chrono::duration_cast<chrono::microseconds>(end1 - start1).count()/iterations 
         << " μs per 1MB\n";

}

TEST_F(Blake2Test, PerformanceTestDifferentSizes) {
    const int iterations = 10;
    const vector<size_t> test_sizes = {
        1024,       // 1 KB
        10 * 1024,   // 10 KB
        100 * 1024,  // 100 KB
        1024 * 1024, // 1 MB
        10 * 1024 * 1024 // 10 MB
    };

    cout << "\nPerformance results (avg per operation):\n";
    cout << "-------------------------------------------------\n";
    cout << "| Size       | Time (μs)  | Speed (MB/s)        |\n";
    cout << "-------------------------------------------------\n";

    for (size_t size : test_sizes) {
        auto test_data = generateRandomData(size);

        auto start = chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i) {
            shsBlake2::hash(test_data);
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
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}