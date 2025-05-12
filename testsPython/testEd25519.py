import pytest
from ShSlibPy import ed25519_create_keypair, ed25519_sign, ed25519_verify
import time
from typing import Tuple
import random

# Unit тесты для Ed25519
class TestEd25519Basic:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.keypair = ed25519_create_keypair()
        self.pub_key, self.priv_key = self.keypair
        self.test_message = "Test message for ed25519 signing"

    def test_key_pair_generation(self):
        """Проверка генерации ключевой пары"""
        assert len(self.pub_key) == 32, "Public key should be 32 bytes"
        assert len(self.priv_key) == 64, "Private key should be 64 bytes"
        
        # Генерируем вторую пару и проверяем что ключи разные
        keypair2 = ed25519_create_keypair()
        assert self.pub_key != keypair2[0], "Public keys should be different"
        assert self.priv_key != keypair2[1], "Private keys should be different"

    def test_sign_and_verify(self):
        """Проверка подписи и верификации"""
        signature = ed25519_sign(self.test_message, self.pub_key, self.priv_key)
        
        assert len(signature) == 64, "Signature should be 64 bytes"
        assert ed25519_verify(self.test_message, signature, self.pub_key), "Signature should be valid"
        
        # Неправильное сообщение
        assert not ed25519_verify("Different message", signature, self.pub_key), \
            "Signature should not verify for different message"
        
        # Неправильный публичный ключ
        keypair2 = ed25519_create_keypair()
        assert not ed25519_verify(self.test_message, signature, keypair2[0]), \
            "Signature should not verify with different public key"

    def test_empty_message(self):
        """Проверка работы с пустым сообщением"""
        empty_msg = ""
        signature = ed25519_sign(empty_msg, self.pub_key, self.priv_key)
        assert len(signature) == 64, "Signature should be 64 bytes even for empty message"
        assert ed25519_verify(empty_msg, signature, self.pub_key), \
            "Empty message signature should verify"

    def test_large_message(self):
        """Проверка работы с большим сообщением"""
        large_msg = "x" * 100000  # 100KB сообщение
        signature = ed25519_sign(large_msg, self.pub_key, self.priv_key)
        assert len(signature) == 64, "Signature should be 64 bytes for large message"
        assert ed25519_verify(large_msg, signature, self.pub_key), \
            "Large message signature should verify"

    def test_invalid_signature(self):
        """Проверка обработки невалидных подписей"""
        signature = ed25519_sign(self.test_message, self.pub_key, self.priv_key)
        
        # Модифицированная подпись
        bad_signature = list(signature)
        bad_signature[0] ^= 0x01
        assert not ed25519_verify(self.test_message, bad_signature, self.pub_key), \
            "Should detect modified signature"
        
        # Слишком короткая подпись
        short_sig = [0xAA] * 63
        assert not ed25519_verify(self.test_message, short_sig, self.pub_key), \
            "Should reject short signature"
        
        # Слишком длинная подпись
        long_sig = [0xAA] * 65
        assert not ed25519_verify(self.test_message, long_sig, self.pub_key), \
            "Should reject long signature"

    def test_deterministic_signatures(self):
        """Проверка детерминированности подписей"""
        sig1 = ed25519_sign(self.test_message, self.pub_key, self.priv_key)
        sig2 = ed25519_sign(self.test_message, self.pub_key, self.priv_key)
        assert sig1 == sig2, "ed25519 signatures should be deterministic"

# Тесты производительности Ed25519
class TestEd25519Performance:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.test_sizes = [0, 32, 256, 1024, 10*1024, 100*1024, 1024*1024]
        self.iterations = 100

    def measure_time(self, func, iterations=1):
        """Измеряет среднее время выполнения функции"""
        # Прогрев
        for _ in range(3):
            func()
        
        start = time.perf_counter()
        for _ in range(iterations):
            func()
        end = time.perf_counter()
        
        return (end - start) * 1_000_000 / iterations  # возвращаем микросекунды

    def test_performance_different_message_sizes(self):
        """Тест производительности для сообщений разного размера"""
        print("\nEd25519 Performance results (avg per operation):")
        print("-----------------------------------------------------------------")
        print("| Message Size | Key Gen (μs) | Sign (μs) | Verify (μs) |")
        print("-----------------------------------------------------------------")

        for size in self.test_sizes:
            message = "x" * size
            
            # Измеряем время генерации ключей
            def keygen_func():
                return ed25519_create_keypair()
            
            gen_time = self.measure_time(keygen_func, self.iterations)
            
            # Измеряем время подписи
            keypair = ed25519_create_keypair()
            
            def sign_func():
                return ed25519_sign(message, keypair[0], keypair[1])
            
            sign_time = self.measure_time(sign_func, self.iterations)
            
            # Измеряем время верификации
            signature = ed25519_sign(message, keypair[0], keypair[1])
            
            def verify_func():
                return ed25519_verify(message, signature, keypair[0])
            
            verify_time = self.measure_time(verify_func, self.iterations)
            
            print(f"| {size:12} | {gen_time:12.2f} | {sign_time:9.2f} | {verify_time:10.2f} |")
        
        print("-----------------------------------------------------------------")

    def test_key_generation_performance(self):
        """Тест производительности генерации ключей"""
        def keygen_func():
            return ed25519_create_keypair()
        
        avg_time = self.measure_time(keygen_func, self.iterations) / 1000  # в миллисекундах
        print(f"\n[PERF] Key generation: {avg_time:.4f} ms")
        assert avg_time < 10.0, "Key generation should be fast (<10ms)"

    def test_sign_verify_performance(self):
        """Тест производительности подписи и верификации"""
        message = "Test message" * 100  # ~1KB сообщение
        keypair = ed25519_create_keypair()
        
        # Измеряем время подписи
        def sign_func():
            return ed25519_sign(message, keypair[0], keypair[1])
        
        sign_time = self.measure_time(sign_func, self.iterations) / 1000  # в миллисекундах
        print(f"[PERF] Sign: {sign_time:.4f} ms")
        assert sign_time < 10.0, "Signing should be fast (<10ms)"
        
        # Измеряем время верификации
        signature = ed25519_sign(message, keypair[0], keypair[1])
        
        def verify_func():
            return ed25519_verify(message, signature, keypair[0])
        
        verify_time = self.measure_time(verify_func, self.iterations) / 1000  # в миллисекундах
        print(f"[PERF] Verify: {verify_time:.4f} ms")
        assert verify_time < 10.0, "Verification should be fast (<10ms)"

