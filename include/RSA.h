#pragma once

#include <algorithm>
#include <exception>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>

extern "C" {
  using largeIntegerType = long long;
}

struct Keys
{
    std::pair<largeIntegerType, largeIntegerType> _public;
    std::pair<largeIntegerType, largeIntegerType> _private;
};

Keys calculateRSAKeys();

largeIntegerType cryptData(largeIntegerType data, std::pair<largeIntegerType, largeIntegerType> _publicKey);

largeIntegerType encryptData(largeIntegerType data, std::pair<largeIntegerType, largeIntegerType> _privateKey);

std::vector<largeIntegerType> cryptMessage(std::vector <largeIntegerType> data, std::pair<largeIntegerType, largeIntegerType> _publicKey);  

std::string encryptMessage(std::vector<largeIntegerType> data, std::pair<largeIntegerType, largeIntegerType> _privateKey);

std::vector<largeIntegerType> confuseData(std::string data, std::pair<largeIntegerType, largeIntegerType>_anyKey);

std::string deconfuseData(std::string confusedData, std::pair<largeIntegerType, largeIntegerType> _anyKey);
