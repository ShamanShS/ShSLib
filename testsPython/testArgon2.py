import pytest
from ShSlibPy import Argon2Hasher
import time
from typing import Tuple
import re

# Unit тесты для Argon2
class TestArgon2Basic:
    def test_hash_password_with_salt_format(self):
        """Проверка формата возвращаемого хеша"""
        result = Argon2Hasher.hashPasswordWithSalt("testPassword")
        assert '$' in result
        
        parts = result.split('$')
        assert len(parts) == 2
        assert len(parts[0]) > 0  # salt
        assert len(parts[1]) > 0  # hash

    def test_hash_password_with_salt_unique_salts(self):
        """Проверка генерации разных солей для одного пароля"""
        result1 = Argon2Hasher.hashPasswordWithSalt("testPassword")
        result2 = Argon2Hasher.hashPasswordWithSalt("testPassword")
        assert result1 != result2

    def test_verify_password_correct(self):
        """Проверка верификации правильного пароля"""
        password = "correctPassword"
        stored_hash = Argon2Hasher.hashPasswordWithSalt(password)
        assert Argon2Hasher.verifyPassword(password, stored_hash)

    def test_verify_password_incorrect(self):
        """Проверка верификации неправильного пароля"""
        password = "correctPassword"
        wrong_password = "wrongPassword"
        stored_hash = Argon2Hasher.hashPasswordWithSalt(password)
        assert not Argon2Hasher.verifyPassword(wrong_password, stored_hash)

    def test_verify_password_tampered_hash(self):
        """Проверка верификации с измененным хешем"""
        password = "testPassword"
        stored_hash = Argon2Hasher.hashPasswordWithSalt(password)
        
        # Изменяем хеш
        parts = stored_hash.split('$')
        tampered_hash = f"{parts[0]}${parts[1][:-1]}x"  # меняем последний символ
        
        assert not Argon2Hasher.verifyPassword(password, tampered_hash)

    def test_custom_parameters(self):
        """Проверка работы с кастомными параметрами"""
        password = "testPassword"
        stored_hash = Argon2Hasher.hashPasswordWithSalt(
            password, 
            t_cost=5, 
            m_cost=65536,  # 64MB
            salt_len=32,
            out_len=64
        )
        
        # Проверяем формат
        parts = stored_hash.split('$')
        assert len(parts[0]) == 32 * 2  # salt в hex
        assert len(parts[1]) == 64 * 2   # hash в hex
        
        # Проверяем верификацию
        assert Argon2Hasher.verifyPassword(
            password, 
            stored_hash,
            t_cost=5,
            m_cost=65536,
            out_len=64
        )

# Тесты производительности Argon2
class TestArgon2Performance:
    @pytest.fixture(autouse=True)
    def setup(self):
        self.test_password = "testPassword123"
        self.iterations = 5

    def measure_time(self, func, iterations=1):
        """Измеряет среднее время выполнения функции"""
        # Прогрев
        for _ in range(2):
            func()
        
        start = time.perf_counter()
        for _ in range(iterations):
            func()
        end = time.perf_counter()
        
        return (end - start) / iterations

    def test_hash_performance_default_params(self):
        """Тест производительности хеширования с параметрами по умолчанию"""
        def hash_func():
            return Argon2Hasher.hashPasswordWithSalt(self.test_password)
        
        avg_time = self.measure_time(hash_func, self.iterations)
        print(f"\n[PERF] Hash (default): {avg_time:.4f} sec")
        
        # Проверяем, что время в разумных пределах (менее 1 сек)
        assert avg_time < 1.0

    def test_verify_performance(self):
        """Тест производительности верификации"""
        stored_hash = Argon2Hasher.hashPasswordWithSalt(self.test_password)
        
        def verify_correct():
            return Argon2Hasher.verifyPassword(self.test_password, stored_hash)
        
        def verify_incorrect():
            return Argon2Hasher.verifyPassword("wrongPassword", stored_hash)
        
        correct_time = self.measure_time(verify_correct, self.iterations)
        incorrect_time = self.measure_time(verify_incorrect, self.iterations)
        
        print(f"[PERF] Verify (correct): {correct_time:.4f} sec")
        print(f"[PERF] Verify (incorrect): {incorrect_time:.4f} sec")
        
        assert correct_time < 1.0
        assert incorrect_time < 1.0

    def test_performance_with_different_parameters(self):
        """Тест производительности с разными параметрами"""
        test_params = [
            ("Fast (t=1, m=16MB)", 1, 1<<16),      # 16MB
            ("Balanced (t=3, m=64MB)", 3, 1<<18),   # 64MB
            ("Secure (t=5, m=256MB)", 5, 1<<20)     # 256MB
        ]
        
        print("\nArgon2 Performance with different parameters:")
        print("| Config                 | Hash (sec) | Verify (sec) |")
        print("|------------------------|------------|--------------|")
        
        for name, t_cost, m_cost in test_params:
            # Измеряем время хеширования
            def hash_func():
                return Argon2Hasher.hashPasswordWithSalt(
                    self.test_password, 
                    t_cost=t_cost, 
                    m_cost=m_cost
                )
            
            hash_time = self.measure_time(hash_func, self.iterations)
            
            # Измеряем время верификации
            stored_hash = hash_func()
            
            def verify_func():
                return Argon2Hasher.verifyPassword(
                    self.test_password, 
                    stored_hash,
                    t_cost=t_cost,
                    m_cost=m_cost
                )
            
            verify_time = self.measure_time(verify_func, self.iterations)
            
            print(f"| {name:<22} | {hash_time:>10.4f} | {verify_time:>12.4f} |")
        
        print("|------------------------|------------|--------------|")

    def test_performance_with_different_password_lengths(self):
        """Тест производительности с паролями разной длины"""
        password_lengths = [
            ("8 chars", "a" * 8),
            ("32 chars", "a" * 32),
            ("1KB", "a" * 1024),
            ("64KB", "a" * 65536)
        ]
        
        print("\nArgon2 Performance with different password lengths (t=3, m=64MB):")
        print("| Password Length | Hash (sec) | Verify (sec) |")
        print("|-----------------|------------|--------------|")
        
        for name, password in password_lengths:
            # Измеряем время хеширования
            def hash_func():
                return Argon2Hasher.hashPasswordWithSalt(
                    password, 
                    t_cost=3, 
                    m_cost=1<<18  # 64MB
                )
            
            hash_time = self.measure_time(hash_func, self.iterations)
            
            # Измеряем время верификации
            stored_hash = hash_func()
            
            def verify_func():
                return Argon2Hasher.verifyPassword(
                    password, 
                    stored_hash,
                    t_cost=3,
                    m_cost=1<<18
                )
            
            verify_time = self.measure_time(verify_func, self.iterations)
            
            print(f"| {name:<15} | {hash_time:>10.4f} | {verify_time:>12.4f} |")
        
        print("|-----------------|------------|--------------|")

    def test_thread_safety(self):
        """Проверка потокобезопасности (если применимо)"""
        from concurrent.futures import ThreadPoolExecutor
        
        stored_hash = Argon2Hasher.hashPasswordWithSalt(self.test_password)
        
        def verify_task(_):
            return Argon2Hasher.verifyPassword(self.test_password, stored_hash)
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(verify_task, range(10)))
        
        assert all(results)
