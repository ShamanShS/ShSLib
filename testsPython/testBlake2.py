import pytest
from ShSlibPy import Blake2b, blake2b_hash, blake2b_hash_bytes, blake2b_hash_keyed, blake2b_hash_keyed_bytes
import secrets
import time
from typing import List
import random

# Фикстуры для тестовых данных
@pytest.fixture
def default_data():
    return "Test message for BLAKE2 hashing"

@pytest.fixture
def random_data():
    return bytes([random.randint(0, 255) for _ in range(1024)])  # 1KB случайных данных

@pytest.fixture
def test_salt():
    return bytes([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])

@pytest.fixture
def test_personal():
    return bytes([16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1])

@pytest.fixture
def test_key():
    return bytes([1,2,3,4,5])

# Unit тесты для Blake2b
class TestBlake2bBasic:
    def test_default_constructor(self, default_data):
        hasher = Blake2b()
        hasher.update(default_data)
        hash_result = hasher.finalize()
        assert len(hash_result) == 64  # Максимальный размер вывода по умолчанию

    def test_keyed_constructor(self, default_data, test_key):
        hasher = Blake2b(key=test_key)
        hasher.update(default_data)
        hash_result = hasher.finalize()
        assert len(hash_result) == 64

    def test_custom_output_length(self, default_data):
        custom_length = 32
        hasher = Blake2b(outlen=custom_length)
        hasher.update(default_data)
        hash_result = hasher.finalize()
        assert len(hash_result) == custom_length

    def test_update_methods(self, default_data):
        hasher = Blake2b()
        
        # Тестируем разные методы update
        hasher.update(default_data)
        hasher.update(default_data.encode())
        hasher.update(bytearray(default_data.encode()))
        
        hash_result = hasher.finalize()
        assert len(hash_result) == 64

    def test_chunked_update(self, random_data):
        hasher1 = Blake2b()
        hasher2 = Blake2b()
        
        # Хеширование всех данных сразу
        hasher1.update(random_data)
        hash1 = hasher1.finalize()
        
        # Хеширование по частям
        chunk_size = 128
        for i in range(0, len(random_data), chunk_size):
            chunk = random_data[i:i+chunk_size]
            hasher2.update(chunk)
        hash2 = hasher2.finalize()
        
        assert hash1 == hash2

    def test_static_hash_methods(self, default_data):
        hash1 = blake2b_hash(default_data)
        hash2 = blake2b_hash_bytes(default_data.encode())
        assert hash1 == hash2
        assert len(hash1) == 64

    def test_static_hash_custom_length(self, default_data):
        custom_length = 32
        hash_result = blake2b_hash(default_data, outlen=custom_length)
        assert len(hash_result) == custom_length

    def test_keyed_hashing(self, default_data, test_key):
        hash1 = blake2b_hash_keyed(default_data, test_key)
        hash2 = blake2b_hash_keyed_bytes(default_data.encode(), test_key)
        
        assert hash1 == hash2
        assert hash1 != blake2b_hash(default_data)  # Должно отличаться от обычного хеша

    def test_empty_input(self):
        empty_data = ""
        hash_result = blake2b_hash(empty_data)
        assert len(hash_result) == 64
        
        empty_bytes = bytes()
        hash_result2 = blake2b_hash_bytes(empty_bytes)
        assert hash_result == hash_result2

    def test_max_key_size(self, default_data):
        max_key = bytes([0xAA] * 64)  # Максимальный размер ключа для BLAKE2b
        hasher = Blake2b(key=max_key)
        hasher.update(default_data)
        hash_result = hasher.finalize()
        assert len(hash_result) == 64

    def test_invalid_output_length(self):
        with pytest.raises(ValueError):
            Blake2b(outlen=0)
        
        with pytest.raises(ValueError):
            Blake2b(outlen=65)  # Максимально допустимый размер - 64
            
        with pytest.raises(ValueError):
            blake2b_hash("test", outlen=0)
            
        with pytest.raises(ValueError):
            blake2b_hash("test", outlen=65)


# Тесты производительности Blake2b
class TestBlake2bPerformance:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.test_sizes = [
            1024,        # 1 KB
            10 * 1024,   # 10 KB
            100 * 1024,  # 100 KB
            1024 * 1024, # 1 MB
            10 * 1024 * 1024  # 10 MB
        ]
        self.iterations = 10

    def generate_test_data(self, size):
        return bytes([random.randint(0, 255) for _ in range(size)])

    def measure_time(self, func, iterations=1):
        """Измеряет среднее время выполнения функции в микросекундах"""
        # Прогрев
        for _ in range(3):
            func()
        
        start = time.perf_counter()
        for _ in range(iterations):
            func()
        end = time.perf_counter()
        
        return (end - start) * 1_000_000 / iterations

    def test_performance_different_sizes(self):
        """Тест производительности для данных разного размера"""
        print("\nBlake2b Performance results (avg per operation):")
        print("-------------------------------------------------")
        print("| Size       | Time (μs)  | Speed (MB/s)        |")
        print("-------------------------------------------------")

        for size in self.test_sizes:
            test_data = list(self.generate_test_data(size))
            
            def hash_func():
                return blake2b_hash_bytes(test_data)
            
            avg_time = self.measure_time(hash_func, self.iterations)
            speed_mbs = (size / (1024 * 1024)) / (avg_time / 1_000_000)
            
            print(f"| {size//1024:>6} KB | {avg_time:>9.1f} | {speed_mbs:>12.2f} MB/s |")
        
        print("-------------------------------------------------")

    