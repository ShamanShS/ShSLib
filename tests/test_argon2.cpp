#include <gtest/gtest.h>
#include "Argon2Hasher.hpp"
#include <vector>
#include <string>
#include <stdexcept>
#include <chrono>
#include <iomanip>
#include <functional>
#include <cstring>

using namespace mylib::crypto;

class Argon2HasherTest : public ::testing::Test {
protected:
    

    std::string makeStoredHash(const std::string& password) {
        return Argon2Hasher::hashPasswordWithSalt(password);
    }
};

TEST_F(Argon2HasherTest, HashPasswordWithSalt_ReturnsValidFormat) {
    auto result = Argon2Hasher::hashPasswordWithSalt("testPassword");
    EXPECT_NE(result.find('$'), std::string::npos);
    
    auto [salt, hash] = Argon2Hasher::splitSaltAndHash(result);
    EXPECT_FALSE(salt.empty());
    EXPECT_FALSE(hash.empty());
}

TEST_F(Argon2HasherTest, HashPasswordWithSalt_GeneratesDifferentSalts) {
    auto result1 = Argon2Hasher::hashPasswordWithSalt("testPassword");
    auto result2 = Argon2Hasher::hashPasswordWithSalt("testPassword");
    EXPECT_NE(result1, result2);
}





class Argon2PerformanceTest : public ::testing::Test {
protected:
    struct BenchmarkResult {
        double avgTimeMs;
        double opsPerSec;
        std::string config;
    };
    
    std::vector<BenchmarkResult> results;
    
    void runBenchmark(const std::string& name, 
                     std::function<void()> func,
                     int runs = 5) {
        // Прогрев гоев
        for (int i = 0; i < 2; ++i) func();
        
        auto start = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < runs; ++i) func();
        auto end = std::chrono::high_resolution_clock::now();
        
        auto totalMs = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        double avgMs = static_cast<double>(totalMs) / runs;
        double opsPerSec = 1000.0 / avgMs * runs;
        
        results.push_back({avgMs, opsPerSec, name});
        
        std::cout << std::fixed << std::setprecision(2);
        std::cout << "[PERF] " << std::setw(25) << std::left << name 
                  << " " << std::setw(8) << avgMs << " ms/op"
                  << " " << std::setw(10) << opsPerSec << " ops/sec\n";
    }
    
    void TearDown() override {
        if (!results.empty()) {
            std::cout << "\nPerformance Summary:\n";
            std::cout << "-----------------------------------------\n";
            for (const auto& r : results) {
                std::cout << std::setw(25) << std::left << r.config 
                          << " " << std::setw(8) << r.avgTimeMs
                          << " " << std::setw(10) << r.opsPerSec << "\n";
            }
            std::cout << "-----------------------------------------\n";
        }
    }
};

TEST_F(Argon2PerformanceTest, HashPerformance) {
    runBenchmark("Default params", []() {
        char pwd[] = "performanceTest";
        auto hash = Argon2Hasher::hashPasswordWithSalt(pwd);
        std::memset(pwd, 0, sizeof("performanceTest"));
    });
    
    runBenchmark("High t_cost", []() {
        char pwd[] = "performanceTest";
        auto hash = Argon2Hasher::hashPasswordWithSalt(pwd, 5);
        std::memset(pwd, 0, sizeof("performanceTest"));
    });
}

TEST_F(Argon2PerformanceTest, VerifyPerformance) {
    const auto stored = Argon2Hasher::hashPasswordWithSalt("testPassword");
    
    runBenchmark("Verify correct", [&stored]() {
        char pwd[] = "testPassword";
        bool result = Argon2Hasher::verifyPassword(pwd, stored);
        std::memset(pwd, 0, sizeof("testPassword"));
    });
    
    runBenchmark("Verify wrong", [&stored]() {
        char pwd[] = "wrongPassword";
        bool result = Argon2Hasher::verifyPassword(pwd, stored);
        std::memset(pwd, 0, sizeof("wrongPassword"));
    });
}

using namespace std;

TEST_F(Argon2PerformanceTest, PerformanceDifferentParameters) {
    const int iterations = 10; 
    const vector<tuple<string, int, size_t>> test_params = {
        {"Fast (t=1, m=16MB)", 1, 1<<16},      
        {"Balanced (t=3, m=64MB)", 3, 1<<18},  
        {"Secure (t=5, m=256MB)", 5, 1<<20}   
    };

    cout << "\nArgon2 Performance results (avg per operation):\n";
    cout << "----------------------------------------------------------------------------\n";
    cout << "| Config                 | Hash (ms) | Verify (ms) | Memory (MB) | Threads |\n";
    cout << "----------------------------------------------------------------------------\n";

    const string test_password = "testPassword123";

    for (const auto& [name, t_cost, m_cost] : test_params) {

        auto start_hash = chrono::high_resolution_clock::now();
        string stored_hash;
        for (int i = 0; i < iterations; ++i) {
            stored_hash = Argon2Hasher::hashPasswordWithSalt(test_password, t_cost, m_cost);
        }
        auto end_hash = chrono::high_resolution_clock::now();
        double hash_time = chrono::duration_cast<chrono::milliseconds>(end_hash - start_hash).count() / iterations;


        auto start_verify = chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i) {
            bool result = Argon2Hasher::verifyPassword(test_password, stored_hash);
        }
        auto end_verify = chrono::high_resolution_clock::now();
        double verify_time = chrono::duration_cast<chrono::milliseconds>(end_verify - start_verify).count() / iterations;

        cout << "| " << setw(22) << left << name << " | "
             << setw(9) << fixed << setprecision(2) << hash_time << " | "
             << setw(11) << verify_time << " | "
             << setw(11) << (m_cost/(1024*1024)) << " | "
             << setw(7) << "1" << " |\n";
    }
    cout << "----------------------------------------------------------------------------\n";


    cout << "\nArgon2 Performance with different password lengths (t=3, m=64MB, p=1):\n";
    cout << "--------------------------------------------------------\n";
    cout << "| Password Length | Hash (ms) | Verify (ms) |\n";
    cout << "--------------------------------------------------------\n";

    const vector<pair<string, size_t>> password_lengths = {
        {"8 chars", 8},
        {"32 chars", 32},
        {"1KB", 1024},
        {"64KB", 65536}
    };

    for (const auto& [desc, length] : password_lengths) {
        string password(length, 'a');
        
        auto start_hash = chrono::high_resolution_clock::now();
        string stored_hash;
        for (int i = 0; i < iterations; ++i) {
            stored_hash = Argon2Hasher::hashPasswordWithSalt(password, 3, 1<<18);
        }
        auto end_hash = chrono::high_resolution_clock::now();
        double hash_time = chrono::duration_cast<chrono::milliseconds>(end_hash - start_hash).count() / iterations;

        auto start_verify = chrono::high_resolution_clock::now();
        for (int i = 0; i < iterations; ++i) {
            bool result = Argon2Hasher::verifyPassword(password, stored_hash);
        }
        auto end_verify = chrono::high_resolution_clock::now();
        double verify_time = chrono::duration_cast<chrono::milliseconds>(end_verify - start_verify).count() / iterations;

        cout << "| " << setw(16) << desc << " | "
             << setw(9) << hash_time << " | "
             << setw(11) << verify_time << " |\n";
    }
    cout << "--------------------------------------------------------\n";
}

