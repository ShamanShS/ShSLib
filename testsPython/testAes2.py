import unittest
import time
from ShSlibPy import AES, AESKeyLength
from typing import List

class TestAES(unittest.TestCase):
    def setUp(self):
        self.aes128 = AES(AESKeyLength.AES_128)
        self.aes192 = AES(AESKeyLength.AES_192)
        self.aes256 = AES(AESKeyLength.AES_256)
        
        self.key128 = [0x11] * 16
        self.key192 = [0x22] * 24
        self.key256 = [0x33] * 32
        self.iv = [0x44] * 16
        
        self.data16 = [ord(c) for c in "Test AES 128!!!!"]
        self.empty_data = []
        self.max_data = [0xAA] * (1024 * 1024)  # 1MB

    # Unit тесты для ECB режима
    def test_encrypt_decrypt_ecb_128(self):
        encrypted = self.aes128.encrypt_ecb(self.data16, self.key128)
        decrypted = self.aes128.decrypt_ecb(encrypted, self.key128)
        self.assertEqual(decrypted, self.data16)

    def test_encrypt_decrypt_ecb_192(self):
        encrypted = self.aes192.encrypt_ecb(self.data16, self.key192)
        decrypted = self.aes192.decrypt_ecb(encrypted, self.key192)
        self.assertEqual(decrypted, self.data16)

    def test_encrypt_decrypt_ecb_256(self):
        encrypted = self.aes256.encrypt_ecb(self.data16, self.key256)
        decrypted = self.aes256.decrypt_ecb(encrypted, self.key256)
        self.assertEqual(decrypted, self.data16)

    # Unit тесты для CBC режима
    def test_encrypt_decrypt_cbc_128(self):
        encrypted = self.aes128.encrypt_cbc(self.data16, self.key128, self.iv)
        decrypted = self.aes128.decrypt_cbc(encrypted, self.key128, self.iv)
        self.assertEqual(decrypted, self.data16)

    def test_encrypt_decrypt_cbc_256(self):
        encrypted = self.aes256.encrypt_cbc(self.data16, self.key256, self.iv)
        decrypted = self.aes256.decrypt_cbc(encrypted, self.key256, self.iv)
        self.assertEqual(decrypted, self.data16)

    def test_cbc_iv_changes_ciphertext(self):
        iv2 = [0x55] * 16
        cipher1 = self.aes128.encrypt_cbc(self.data16, self.key128, self.iv)
        cipher2 = self.aes128.encrypt_cbc(self.data16, self.key128, iv2)
        self.assertNotEqual(cipher1, cipher2)

    # Unit тесты для CFB режима
    def test_encrypt_decrypt_cfb_128(self):
        encrypted = self.aes128.encrypt_cfb(self.data16, self.key128, self.iv)
        decrypted = self.aes128.decrypt_cfb(encrypted, self.key128, self.iv)
        self.assertEqual(decrypted, self.data16)

    def test_cfb_iv_changes_ciphertext(self):
        iv2 = [0x55] * 16
        cipher1 = self.aes128.encrypt_cfb(self.data16, self.key128, self.iv)
        cipher2 = self.aes128.encrypt_cfb(self.data16, self.key128, iv2)
        self.assertNotEqual(cipher1, cipher2)

    # Тесты с пустыми данными
    def test_cbc_empty_data(self):
        encrypted = self.aes128.encrypt_cbc(self.empty_data, self.key128, self.iv)
        decrypted = self.aes128.decrypt_cbc(encrypted, self.key128, self.iv)
        self.assertEqual(decrypted, self.empty_data)

    def test_cfb_empty_data(self):
        encrypted = self.aes128.encrypt_cfb(self.empty_data, self.key128, self.iv)
        decrypted = self.aes128.decrypt_cfb(encrypted, self.key128, self.iv)
        self.assertEqual(decrypted, self.empty_data)

    # Тесты с большими данными
    def test_ecb_large_data(self):
        encrypted = self.aes256.encrypt_ecb(self.max_data, self.key256)
        decrypted = self.aes256.decrypt_ecb(encrypted, self.key256)
        self.assertEqual(decrypted, self.max_data)

    # Тесты на устойчивость к изменениям
    def test_cbc_tampered_ciphertext(self):
        encrypted = self.aes128.encrypt_cbc(self.data16, self.key128, self.iv)
        encrypted[5] ^= 0x01  # Изменяем один байт
        decrypted = self.aes128.decrypt_cbc(encrypted, self.key128, self.iv)
        self.assertNotEqual(decrypted, self.data16)

    def test_cfb_tampered_ciphertext(self):
        encrypted = self.aes128.encrypt_cfb(self.data16, self.key128, self.iv)
        encrypted[5] ^= 0x01  # Изменяем один байт
        decrypted = self.aes128.decrypt_cfb(encrypted, self.key128, self.iv)
        self.assertNotEqual(decrypted, self.data16)

    # Тесты с неверным ключом
    def test_wrong_key_ecb(self):
        encrypted = self.aes128.encrypt_ecb(self.data16, self.key128)
        wrong_key = [0xFF] * 16
        decrypted = self.aes128.decrypt_ecb(encrypted, wrong_key)
        self.assertNotEqual(decrypted, self.data16)

    def test_wrong_key_cbc(self):
        encrypted = self.aes128.encrypt_cbc(self.data16, self.key128, self.iv)
        wrong_key = [0xFF] * 16
        decrypted = self.aes128.decrypt_cbc(encrypted, wrong_key, self.iv)
        self.assertNotEqual(decrypted, self.data16)

    # Тесты на детерминированность
    def test_ecb_deterministic(self):
        encrypted1 = self.aes128.encrypt_ecb(self.data16, self.key128)
        encrypted2 = self.aes128.encrypt_ecb(self.data16, self.key128)
        self.assertEqual(encrypted1, encrypted2)

    def test_cbc_non_deterministic(self):
        encrypted1 = self.aes128.encrypt_cbc(self.data16, self.key128, self.iv)
        encrypted2 = self.aes128.encrypt_cbc(self.data16, self.key128, self.iv)
        self.assertEqual(encrypted1, encrypted2)
        
        iv2 = [0x55] * 16
        encrypted3 = self.aes128.encrypt_cbc(self.data16, self.key128, iv2)
        self.assertNotEqual(encrypted1, encrypted3)


class TestAESPerformance(unittest.TestCase):
    def setUp(self):
        self.aes = AES(AESKeyLength.AES_128)
        self.key128 = [0x11] * 16
        self.key256 = [0x33] * 32
        self.iv = [0x44] * 16
        
        self.data_sizes = {
            "1K": 1024,
            "10K": 10240,
            "100K": 102400,
            "1M": 1024 * 1024,
            "10M": 10 * 1024 * 1024
        }
        
        self.test_data = {size: [0xAA] * length for size, length in self.data_sizes.items()}

    def measure_performance(self, operation_name: str, operation: callable, data_size: str):
        data = self.test_data[data_size]
        size_kb = len(data) // 1024
        
        # Прогрев
        for _ in range(3):
            operation(data)
        
        # Замер времени
        runs = 10
        start = time.perf_counter()
        for _ in range(runs):
            operation(data)
        end = time.perf_counter()
        
        total_time = end - start
        avg_time = total_time / runs
        speed = (len(data) * runs) / total_time / (1024 * 1024)  # MB/s
        
        print(f"[PERF] {operation_name} ({size_kb} KB): "
              f"avg {avg_time:.4f} sec, {speed:.2f} MB/s")

    def test_ecb_128_performance(self):
        print("\nECB 128-bit performance:")
        for size in ["1K", "10K", "100K", "1M", "10M"]:
            self.measure_performance(
                "ECB encrypt-decrypt",
                lambda d: self.aes.decrypt_ecb(self.aes.encrypt_ecb(d, self.key128), self.key128),
                size
            )

    def test_cbc_128_performance(self):
        print("\nCBC 128-bit performance:")
        for size in ["1K", "1M"]:
            self.measure_performance(
                "CBC encrypt-decrypt",
                lambda d: self.aes.decrypt_cbc(self.aes.encrypt_cbc(d, self.key128, self.iv), self.key128, self.iv),
                size
            )

    def test_cfb_128_performance(self):
        print("\nCFB 128-bit performance:")
        for size in ["1K", "1M"]:
            self.measure_performance(
                "CFB encrypt-decrypt",
                lambda d: self.aes.decrypt_cfb(self.aes.encrypt_cfb(d, self.key128, self.iv), self.key128, self.iv),
                size
            )

    def test_compare_modes_performance(self):
        print("\nComparing encryption modes with 1MB data (128-bit key):")
        data = self.test_data["1M"]
        
        # ECB
        start = time.perf_counter()
        encrypted = self.aes.encrypt_ecb(data, self.key128)
        decrypted = self.aes.decrypt_ecb(encrypted, self.key128)
        ecb_time = time.perf_counter() - start
        
        # CBC
        start = time.perf_counter()
        encrypted = self.aes.encrypt_cbc(data, self.key128, self.iv)
        decrypted = self.aes.decrypt_cbc(encrypted, self.key128, self.iv)
        cbc_time = time.perf_counter() - start
        
        # CFB
        start = time.perf_counter()
        encrypted = self.aes.encrypt_cfb(data, self.key128, self.iv)
        decrypted = self.aes.decrypt_cfb(encrypted, self.key128, self.iv)
        cfb_time = time.perf_counter() - start
        
        print(f"ECB: {ecb_time:.4f} sec")
        print(f"CBC: {cbc_time:.4f} sec")
        print(f"CFB: {cfb_time:.4f} sec")

    def test_compare_key_sizes_performance(self):
        print("\nComparing key sizes with 1MB data (ECB mode):")
        data = self.test_data["1M"]
        
        # 128-bit
        aes128 = AES(AESKeyLength.AES_128)
        start = time.perf_counter()
        encrypted = aes128.encrypt_ecb(data, self.key128)
        decrypted = aes128.decrypt_ecb(encrypted, self.key128)
        time128 = time.perf_counter() - start
        
        # 256-bit
        aes256 = AES(AESKeyLength.AES_256)
        start = time.perf_counter()
        encrypted = aes256.encrypt_ecb(data, self.key256)
        decrypted = aes256.decrypt_ecb(encrypted, self.key256)
        time256 = time.perf_counter() - start
        
        print(f"AES-128: {time128:.4f} sec")
        print(f"AES-256: {time256:.4f} sec")
        print(f"Ratio (256/128): {time256/time128:.2f}")


if __name__ == '__main__':
    unittest.main(verbosity=2)