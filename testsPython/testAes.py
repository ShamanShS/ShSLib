import pytest
from ShSlibPy import AES, AESKeyLength
import secrets
import time
from typing import List
from concurrent.futures import ThreadPoolExecutor

# Фикстуры для тестовых данных
@pytest.fixture
def aes128():
    return AES(AESKeyLength.AES_128)

@pytest.fixture
def aes192():
    return AES(AESKeyLength.AES_192)

@pytest.fixture
def aes256():
    return AES(AESKeyLength.AES_256)

@pytest.fixture
def key128():
    return [0x11] * 16

@pytest.fixture
def key192():
    return [0x22] * 24

@pytest.fixture
def key256():
    return [0x33] * 32

@pytest.fixture
def iv():
    return [0x44] * 16

@pytest.fixture
def data16():
    return [ord(c) for c in "Test AES 128!!!!"]

@pytest.fixture
def empty_data():
    return []

@pytest.fixture
def max_data():
    return [0xAA] * (1024 * 1024)  # 1MB

@pytest.fixture
def random_key128():
    return [secrets.randbits(8) for _ in range(16)]

@pytest.fixture
def random_key256():
    return [secrets.randbits(8) for _ in range(32)]

@pytest.fixture
def random_iv():
    return [secrets.randbits(8) for _ in range(16)]

@pytest.fixture(params=[15, 16, 17, 31, 32, 33, 1023, 1024, 1025])
def random_data(request):
    return [secrets.randbits(8) for _ in range(request.param)]

# Unit тесты
class TestAESBasic:
    def test_encrypt_decrypt_ecb_128(self, aes128, key128, data16):
        encrypted = aes128.encrypt_ecb(data16, key128)
        decrypted = aes128.decrypt_ecb(encrypted, key128)
        assert decrypted == data16

    def test_encrypt_decrypt_ecb_192(self, aes192, key192, data16):
        encrypted = aes192.encrypt_ecb(data16, key192)
        decrypted = aes192.decrypt_ecb(encrypted, key192)
        assert decrypted == data16

    def test_encrypt_decrypt_ecb_256(self, aes256, key256, data16):
        encrypted = aes256.encrypt_ecb(data16, key256)
        decrypted = aes256.decrypt_ecb(encrypted, key256)
        assert decrypted == data16

    def test_encrypt_decrypt_cbc_128(self, aes128, key128, iv, data16):
        encrypted = aes128.encrypt_cbc(data16, key128, iv)
        decrypted = aes128.decrypt_cbc(encrypted, key128, iv)
        assert decrypted == data16

    def test_encrypt_decrypt_cbc_256(self, aes256, key256, iv, data16):
        encrypted = aes256.encrypt_cbc(data16, key256, iv)
        decrypted = aes256.decrypt_cbc(encrypted, key256, iv)
        assert decrypted == data16

    def test_cbc_iv_changes_ciphertext(self, aes128, key128, iv, data16):
        iv2 = [0x55] * 16
        cipher1 = aes128.encrypt_cbc(data16, key128, iv)
        cipher2 = aes128.encrypt_cbc(data16, key128, iv2)
        assert cipher1 != cipher2

    def test_encrypt_decrypt_cfb_128(self, aes128, key128, iv, data16):
        encrypted = aes128.encrypt_cfb(data16, key128, iv)
        decrypted = aes128.decrypt_cfb(encrypted, key128, iv)
        assert decrypted == data16

    def test_cfb_iv_changes_ciphertext(self, aes128, key128, iv, data16):
        iv2 = [0x55] * 16
        cipher1 = aes128.encrypt_cfb(data16, key128, iv)
        cipher2 = aes128.encrypt_cfb(data16, key128, iv2)
        assert cipher1 != cipher2

    def test_cbc_empty_data(self, aes128, key128, iv, empty_data):
        encrypted = aes128.encrypt_cbc(empty_data, key128, iv)
        decrypted = aes128.decrypt_cbc(encrypted, key128, iv)
        assert decrypted == empty_data

    def test_cfb_empty_data(self, aes128, key128, iv, empty_data):
        encrypted = aes128.encrypt_cfb(empty_data, key128, iv)
        decrypted = aes128.decrypt_cfb(encrypted, key128, iv)
        assert decrypted == empty_data

    def test_ecb_large_data(self, aes256, key256, max_data):
        encrypted = aes256.encrypt_ecb(max_data, key256)
        decrypted = aes256.decrypt_ecb(encrypted, key256)
        assert decrypted == max_data

    def test_cbc_tampered_ciphertext(self, aes128, key128, iv, data16):
        encrypted = aes128.encrypt_cbc(data16, key128, iv)
        encrypted[5] ^= 0x01  # Изменяем один байт
        decrypted = aes128.decrypt_cbc(encrypted, key128, iv)
        assert decrypted != data16

    def test_cfb_tampered_ciphertext(self, aes128, key128, iv, data16):
        encrypted = aes128.encrypt_cfb(data16, key128, iv)
        encrypted[5] ^= 0x01  # Изменяем один байт
        decrypted = aes128.decrypt_cfb(encrypted, key128, iv)
        assert decrypted != data16

    def test_wrong_key_ecb(self, aes128, key128, data16):
        encrypted = aes128.encrypt_ecb(data16, key128)
        wrong_key = [0xFF] * 16
        decrypted = aes128.decrypt_ecb(encrypted, wrong_key)
        assert decrypted != data16

    def test_wrong_key_cbc(self, aes128, key128, iv, data16):
        encrypted = aes128.encrypt_cbc(data16, key128, iv)
        wrong_key = [0xFF] * 16
        decrypted = aes128.decrypt_cbc(encrypted, wrong_key, iv)
        assert decrypted != data16

    def test_ecb_deterministic(self, aes128, key128, data16):
        encrypted1 = aes128.encrypt_ecb(data16, key128)
        encrypted2 = aes128.encrypt_ecb(data16, key128)
        assert encrypted1 == encrypted2

    def test_cbc_non_deterministic(self, aes128, key128, iv, data16):
        encrypted1 = aes128.encrypt_cbc(data16, key128, iv)
        encrypted2 = aes128.encrypt_cbc(data16, key128, iv)
        assert encrypted1 == encrypted2
        
        iv2 = [0x55] * 16
        encrypted3 = aes128.encrypt_cbc(data16, key128, iv2)
        assert encrypted1 != encrypted3



# Тесты производительности
class TestAESPerformance:
    @pytest.fixture(autouse=True)
    def setup(self, aes128, key128, iv):
        self.aes = aes128
        self.key128 = key128
        self.iv = iv
        self.data_sizes = {
            "1K": 1024,
            "10K": 10240,
            "100K": 102400,
            "1M": 1024 * 1024,
            "10M": 10 * 1024 * 1024
        }
        self.test_data = {size: [0xAA] * length for size, length in self.data_sizes.items()}

    def measure_performance(self, operation_name, operation, data_size):
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
                "ECB encrypt",
                lambda d: self.aes.encrypt_ecb(d, self.key128),
                size
            )

    def test_cbc_128_performance(self):
        print("\nCBC 128-bit performance:")
        for size in ["1K", "1M"]:
            self.measure_performance(
                "CBC encrypt",
                lambda d: self.aes.encrypt_cbc(d, self.key128, self.iv),
                size
            )

    def test_cfb_128_performance(self):
        print("\nCFB 128-bit performance:")
        for size in ["1K", "1M"]:
            self.measure_performance(
                "CFB encrypt",
                lambda d: self.aes.encrypt_cfb(d, self.key128, self.iv),
                size
            )

    def test_compare_modes_performance(self):
        print("\nComparing encryption modes with 1MB data (128-bit key):")
        data = self.test_data["1M"]
        
        # ECB
        start = time.perf_counter()
        self.aes.encrypt_ecb(data, self.key128)
        ecb_time = time.perf_counter() - start
        
        # CBC
        start = time.perf_counter()
        self.aes.encrypt_cbc(data, self.key128, self.iv)
        cbc_time = time.perf_counter() - start
        
        # CFB
        start = time.perf_counter()
        self.aes.encrypt_cfb(data, self.key128, self.iv)
        cfb_time = time.perf_counter() - start
        
        print(f"ECB: {ecb_time:.4f} sec")
        print(f"CBC: {cbc_time:.4f} sec")
        print(f"CFB: {cfb_time:.4f} sec")

    def test_compare_key_sizes_performance(self, aes256, key256):
        print("\nComparing key sizes with 1MB data (ECB mode):")
        data = self.test_data["1M"]
        
        # 128-bit
        start = time.perf_counter()
        self.aes.encrypt_ecb(data, self.key128)
        time128 = time.perf_counter() - start
        
        # 256-bit
        start = time.perf_counter()
        aes256.encrypt_ecb(data, key256)
        time256 = time.perf_counter() - start
        
        print(f"AES-128: {time128:.4f} sec")
        print(f"AES-256: {time256:.4f} sec")
        print(f"Ratio (256/128): {time256/time128:.2f}")