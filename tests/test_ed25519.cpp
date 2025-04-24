    #include <gtest/gtest.h>
    #include "ed25519_wrapper.hpp"
    #include <vector>
    #include <string>
    #include <algorithm>
    #include <cstring>
    #include <iomanip>
    #include <functional>
    #include <array>
    #include <random>

    using namespace mylib::crypto::ed25519;

    class Ed25519Test : public ::testing::Test {
    protected:
        void SetUp() override {
            keypair = create_keypair();
            pub_key = keypair.first;
            priv_key = keypair.second;
            
            test_message = "Test message for ed25519 signing";
        }

        std::pair<std::vector<uint8_t>, std::vector<uint8_t>> keypair;
        std::vector<uint8_t> pub_key;
        std::vector<uint8_t> priv_key;
        std::string test_message;
    };

    TEST_F(Ed25519Test, KeyPairGeneration) {
        EXPECT_EQ(pub_key.size(), 32) << "Public key should be 32 bytes";
        EXPECT_EQ(priv_key.size(), 64) << "Private key should be 64 bytes";
        
        // Генерируем вторую пару и проверяем что ключи разные
        auto keypair2 = create_keypair();
        EXPECT_NE(keypair.first, keypair2.first) << "Public keys should be different";
        EXPECT_NE(keypair.second, keypair2.second) << "Private keys should be different";
    }

    TEST_F(Ed25519Test, SignAndVerify) {
        auto signature = sign(test_message, pub_key, priv_key);
        
        EXPECT_EQ(signature.size(), 64) << "Signature should be 64 bytes";
        
        EXPECT_TRUE(verify(test_message, signature, pub_key)) << "Signature should be valid";
        
        EXPECT_FALSE(verify("Different message", signature, pub_key)) << "Signature should not verify for different message";
        
        auto keypair2 = create_keypair();
        EXPECT_FALSE(verify(test_message, signature, keypair2.first)) << "Signature should not verify with different public key";
    }


    TEST_F(Ed25519Test, EmptyMessage) {
        std::string empty_msg;
        auto signature = sign(empty_msg, pub_key, priv_key);
        EXPECT_EQ(signature.size(), 64) << "Signature should be 64 bytes even for empty message";
        EXPECT_TRUE(verify(empty_msg, signature, pub_key)) << "Empty message signature should verify";
    }

    TEST_F(Ed25519Test, LargeMessage) {
        std::string large_msg(100000, 'x'); // 100KB сообщение
        auto signature = sign(large_msg, pub_key, priv_key);
        EXPECT_EQ(signature.size(), 64) << "Signature should be 64 bytes for large message";
        EXPECT_TRUE(verify(large_msg, signature, pub_key)) << "Large message signature should verify";
    }


    TEST_F(Ed25519Test, InvalidSignature) {
        auto signature = sign(test_message, pub_key, priv_key);
        
        std::vector<uint8_t> bad_signature = signature;
        bad_signature[0] ^= 0x01;
        
        EXPECT_FALSE(verify(test_message, bad_signature, pub_key)) << "Should detect modified signature";
        
        std::vector<uint8_t> short_sig(63, 0xAA);
        EXPECT_FALSE(verify(test_message, short_sig, pub_key)) << "Should reject short signature";
        
        std::vector<uint8_t> long_sig(65, 0xAA);
        EXPECT_FALSE(verify(test_message, long_sig, pub_key)) << "Should reject long signature";
    }

    TEST_F(Ed25519Test, DeterministicSignatures) {
        auto sig1 = sign(test_message, pub_key, priv_key);
        auto sig2 = sign(test_message, pub_key, priv_key);
        EXPECT_EQ(sig1, sig2) << "ed25519 signatures should be deterministic";
    }


    using namespace std;

    TEST_F(Ed25519Test, PerformanceDifferentMessageSizes) {
        const int iterations = 100;
        const vector<size_t> test_sizes = {
            0,          
            32,        
            256,       
            1024,       
            10 * 1024, 
            100 * 1024, 
            1024 * 1024 
        };

        cout << "\nEd25519 Performance results (avg per operation):\n";
        cout << "-----------------------------------------------------------------\n";
        cout << "| Message Size | Key Gen (μs) | Sign (μs) | Verify (μs) |\n";
        cout << "-----------------------------------------------------------------\n";

        for (size_t size : test_sizes) {
            string message(size, 'x');
            
            auto start_gen = chrono::high_resolution_clock::now();
            for (int i = 0; i < iterations; ++i) {
                auto kp = create_keypair();
            }
            auto end_gen = chrono::high_resolution_clock::now();
            double gen_time = chrono::duration_cast<chrono::microseconds>(end_gen - start_gen).count() / iterations;

            auto kp = create_keypair();
            auto start_sign = chrono::high_resolution_clock::now();
            vector<uint8_t> signature;
            for (int i = 0; i < iterations; ++i) {
                signature = sign(message, kp.first, kp.second);
            }
            auto end_sign = chrono::high_resolution_clock::now();
            double sign_time = chrono::duration_cast<chrono::microseconds>(end_sign - start_sign).count() / iterations;

            auto start_verify = chrono::high_resolution_clock::now();
            for (int i = 0; i < iterations; ++i) {
                verify(message, signature, kp.first);
            }
            auto end_verify = chrono::high_resolution_clock::now();
            double verify_time = chrono::duration_cast<chrono::microseconds>(end_verify - start_verify).count() / iterations;

            cout << "| " << setw(12) << size << " | "
                << setw(12) << fixed << setprecision(2) << gen_time << " | "
                << setw(9) << sign_time << " | "
                << setw(10) << verify_time << " |\n";
        }
        cout << "-----------------------------------------------------------------\n";
    }

