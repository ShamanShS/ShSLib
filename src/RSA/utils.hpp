#pragma once 

#include <iostream>
#include <cmath>
#include <vector>

using largeIntegerType = long long;

largeIntegerType gcd(largeIntegerType a, largeIntegerType b);

bool prime(largeIntegerType n);

largeIntegerType fastPow(largeIntegerType a, largeIntegerType step, largeIntegerType mod);

std::string to_string(std::vector <largeIntegerType> a);