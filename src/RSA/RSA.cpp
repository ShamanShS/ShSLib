#include "../../include/RSA.h"
#include "utils.hpp"



Keys calculateRSAKeys()
{
    std::vector <largeIntegerType> primes(1034);
    std::ifstream fin("primes.txt");
    for(int i = 0; i < 1033; i++)
    {
        int temp;
        fin >> temp;
        primes[i] = temp;
    }

    largeIntegerType p = primes[rand() % 1033];
    largeIntegerType q = primes[rand() % 1033];

    largeIntegerType n = p * q;

    largeIntegerType functionE = (p - 1) * (q - 1);

    largeIntegerType e = 1;
    for (largeIntegerType i = functionE - 1; i > 0; --i)
    {
        if (gcd(i, functionE) == 1 && prime(i))
        {
            e = i;
            break;
        }
    }

    largeIntegerType d;
    for (largeIntegerType i = 0;; ++i)
    {
        if ((largeIntegerType)i * (largeIntegerType)e % (largeIntegerType)functionE == 1)
        {
            d = i;
            break;
        }
    }

    Keys keys{std::pair<largeIntegerType, largeIntegerType>{e, n}, std::pair<largeIntegerType, largeIntegerType>{d, n}};
    return keys;
}

largeIntegerType cryptData(largeIntegerType data, std::pair<largeIntegerType, largeIntegerType> _publicKey)
{
    return fastPow(data, _publicKey.first, _publicKey.second);
}

largeIntegerType encryptData(largeIntegerType data, std::pair<largeIntegerType, largeIntegerType> _privateKey)
{
    return fastPow(data, _privateKey.first, _privateKey.second);
}

std::vector<largeIntegerType> cryptMessage(std::vector <largeIntegerType> data, std::pair<largeIntegerType, largeIntegerType> _publicKey)
{
    std::vector<largeIntegerType> cryptedMessage;
    cryptedMessage.reserve(data.size());
    for (auto element : data)
    {
        cryptedMessage.push_back(cryptData(element, _publicKey));
    }

    return cryptedMessage;
}

std::string encryptMessage(std::vector<largeIntegerType> data, std::pair<largeIntegerType, largeIntegerType> _privateKey)
{
    std::string encryptedMessage;

    for (largeIntegerType element : data)
    {
        encryptedMessage.push_back(encryptData(element, _privateKey));
    }

    return encryptedMessage;
}

std::vector<largeIntegerType> confuseData(std::string data, std::pair<largeIntegerType, largeIntegerType> _anyKey)
{
    std::vector<largeIntegerType> confusedData;
    confusedData.reserve(data.size());
    if (data.size() == 0)
    {
        return confusedData;
    }

    largeIntegerType startValue = rand() % 10000 + 100;
    confusedData.push_back(startValue);

    for (int i = 0; i < data.size(); ++i)
    {
        confusedData.push_back(((largeIntegerType)data[i] + confusedData[i]) % _anyKey.second % 256);
    }
    return confusedData;
}

std::string deconfuseData(std::string confusedData, std::pair<largeIntegerType, largeIntegerType> _anyKey)
{
    std::string data;

    for (int i = 1; i < confusedData.size(); ++i)
    {
        data.push_back((confusedData[i] - confusedData[i - 1]) % _anyKey.second % 256);
    }
    return data;
}