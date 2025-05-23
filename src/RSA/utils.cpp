#include "utils.hpp"


largeIntegerType gcd(largeIntegerType a, largeIntegerType b)
{
    while (a != b)
    {
        if (a > b)
        {
            largeIntegerType tmp = a;
            a = b;
            b = tmp;
        }
        b = b - a;
    }
    return a;
}

bool prime(largeIntegerType n)
{
    for (largeIntegerType i = 2; i <= sqrt(n); i++)
        if (n % i == 0)
            return false;
    return true;
}

largeIntegerType fastPow(largeIntegerType a, largeIntegerType step, largeIntegerType mod)
{
    if (step == 0)
    {
        return 1;
    }
    if (step % 2 == 1)
    {
        return (fastPow(a, step - 1, mod)) * a % mod;
    }
    else
    {
        largeIntegerType b = fastPow(a, step / 2, mod);
        b %= mod;
        return (b * b)%mod;
    }
}

std::string to_string(std::vector <largeIntegerType> a)
{
    std::string ans;
    for (auto i:a) ans+= i + '0';
    return ans;
}
