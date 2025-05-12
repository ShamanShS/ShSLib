import pytest
from ShSlibPy import SHA512, sha512_hash, sha512_hash_bytes
import secrets
import time
from typing import List
import random
import hashlib  # Для сравнения с эталонной реализацией

# Фикстуры для тестовых данных
@pytest.fixture
def test_string():
    return "Hello, SHA-512!"

@pytest.fixture
def test_vector():
    return [ord(c) for c in "Test data"]

@pytest.fixture
def large_data():
    return bytes([random.randint(0, 255) for _ in range(1024 * 1024)])  # 1MB данных

@pytest.fixture
def empty_data():
    return bytes()

# Unit тесты для SHA512
class TestSHA512Basic:
    def test_construction(self):
        """Проверка создания и уничтожения хешера"""
        hasher = SHA512()
        assert hasher is not None

    def test_update_with_string(self, test_string):
        """Проверка обновления строкой"""
        hasher = SHA512()
        hasher.update(test_string)
        hash_result = hasher.finalize()
        assert len(hash_result) == 64

    def test_update_with_vector(self, test_vector):
        """Проверка обновления списком байтов"""
        hasher = SHA512()
        hasher.update_bytes(test_vector)
        hash_result = hasher.finalize()
        assert len(hash_result) == 64

    def test_update_with_bytes(self, test_string):
        """Проверка обновления байтами"""
        hasher = SHA512()
        hasher.update_bytes(test_string.encode())
        hash_result = hasher.finalize()
        assert len(hash_result) == 64

    def test_chunked_update(self, large_data):
        """Проверка пошагового обновления"""
        hasher1 = SHA512()
        hasher2 = SHA512()

        # Хеширование всех данных сразу
        hasher1.update_bytes(large_data)
        hash1 = hasher1.finalize()

        # Хеширование по частям
        chunk_size = 128
        for i in range(0, len(large_data), chunk_size):
            chunk = large_data[i:i+chunk_size]
            hasher2.update_bytes(chunk)
        hash2 = hasher2.finalize()

        assert hash1 == hash2

    def test_static_hash_string(self, test_string):
        """Проверка статического хеширования строки"""
        hash_result = sha512_hash(test_string)
        assert len(hash_result) == 64

    def test_static_hash_bytes(self, test_string):
        """Проверка статического хеширования байтов"""
        hash_result = sha512_hash_bytes(test_string.encode())
        assert len(hash_result) == 64

    def test_empty_input(self, empty_data):
        """Проверка хеширования пустых данных"""
        hasher = SHA512()
        hasher.update_bytes(empty_data)
        hash1 = hasher.finalize()

        hash2 = sha512_hash_bytes(empty_data)
        hash3 = sha512_hash("")

        assert hash1 == hash2
        assert hash1 == hash3

    def test_large_input(self, large_data):
        """Проверка хеширования больших данных"""
        hash_result = sha512_hash_bytes(large_data)
        assert len(hash_result) == 64

    def test_deterministic_hashing(self, test_string):
        """Проверка детерминированности хеширования"""
        hash1 = sha512_hash(test_string)
        hash2 = sha512_hash(test_string)
        assert hash1 == hash2

        hasher1 = SHA512()
        hasher1.update(test_string)
        hash3 = hasher1.finalize()

        hasher2 = SHA512()
        hasher2.update(test_string)
        hash4 = hasher2.finalize()

        assert hash1 == hash3
        assert hash3 == hash4

    def test_known_hash_values(self):
        """Проверка известных значений хешей"""
        # Пустая строка
        empty_hash = sha512_hash("")
        expected_empty = [
            0xcf, 0x83, 0xe1, 0x35, 0x7e, 0xef, 0xb8, 0xbd, 
            0xf1, 0x54, 0x28, 0x50, 0xd6, 0x6d, 0x80, 0x07,
            0xd6, 0x20, 0xe4, 0x05, 0x0b, 0x57, 0x15, 0xdc,
            0x83, 0xf4, 0xa9, 0x21, 0xd3, 0x6c, 0xe9, 0xce,
            0x47, 0xd0, 0xd1, 0x3c, 0x5d, 0x85, 0xf2, 0xb0,
            0xff, 0x83, 0x18, 0xd2, 0x87, 0x7e, 0xec, 0x2f,
            0x63, 0xb9, 0x31, 0xbd, 0x47, 0x41, 0x7a, 0x81,
            0xa5, 0x38, 0x32, 0x7a, 0xf9, 0x27, 0xda, 0x3e
        ]
        assert empty_hash == expected_empty

        # Строка "abc"
        abc_hash = sha512_hash("abc")
        expected_abc = [
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 
            0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
            0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2,
            0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
            0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8,
            0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
            0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
            0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
        ]
        assert abc_hash == expected_abc

    def test_compatibility_with_hashlib(self, test_string):
        """Сравнение с hashlib.sha512 (эталонной реализацией)"""
        # Тестируем нашу реализацию
        our_hash = sha512_hash(test_string)
        
        # Эталонная реализация
        ref_hash = hashlib.sha512(test_string.encode()).digest()
        ref_hash_list = list(ref_hash)
        
        assert our_hash == ref_hash_list, "Our implementation should match hashlib.sha512"

# Тесты производительности SHA512
class TestSHA512Performance:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.test_sizes = [
            1024,        # 1 KB
            10 * 1024,   # 10 KB
            100 * 1024,  # 100 KB
            1024 * 1024, # 1 MB
            10 * 1024 * 1024  # 10 MB
        ]
        self.iterations = 2

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
        print("\nSHA-512 Performance results (avg per operation):")
        print("-------------------------------------------------")
        print("| Size       | Time (μs)  | Speed (MB/s)        |")
        print("-------------------------------------------------")

        for size in self.test_sizes:
            test_data = list(self.generate_test_data(size))
            
            def hash_func():
                return sha512_hash_bytes(test_data)
            
            avg_time = self.measure_time(hash_func, self.iterations)
            speed_mbs = (size / (1024 * 1024)) / (avg_time / 1_000_000)
            
            print(f"| {size//1024:>6} KB | {avg_time:>9.1f} | {speed_mbs:>12.2f} MB/s |")
        
        print("-------------------------------------------------")


