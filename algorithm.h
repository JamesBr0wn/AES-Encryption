#include "configure.h"
#ifndef AES_H
#define AES_H

enum EncryptType{
    AES128,
    AES192,
    AES256
};

enum WorkMode{
    ECB,
    CBC,
};

class AES{
public:
    AES(EncryptType type);
    ~AES();
    void Encrypt(std::bitset<8> data[16]);
    void Decrypt(std::bitset<8> data[16]);
    void SetKey(std::bitset<8>* key);
    void ByteSub(std::bitset<8> data[16]);
    void RowShift(std::bitset<8> data[16]);
    void InvRowShift(std::bitset<8> data[16]);
    void InvByteSub(std::bitset<8> data[16]);
    void ColumnMix(std::bitset<8> data[16]);
    void InvColumnMix(std::bitset<8> data[16]);
    void RoundKeyAdd(std::bitset<8> data[16], std::bitset<32> key[4]);
    void KeyExpend(std::bitset<8>* originKey, std::bitset<32>* expendedKey);
    std::bitset<32> WordGenerate(std::bitset<8> bytes[4]);
    std::bitset<32> WordRot(std::bitset<32>& word);
    std::bitset<32> WordSub(std::bitset<32>& word);
//private:
    int keyLength, roundNum;
    std::bitset<8>* keyPtr;
    std::bitset<32>* expendedKeyPtr;
};

class AESWrapper{
public:
    AESWrapper(EncryptType type, WorkMode mode);
    void SetKey(std::string keyStr);
    std::string Encrypt(std::string data);
    std::string Decrypt(std::string data);
private:
    EncryptType type;
    WorkMode mode;
    AES aes;
};

#endif // AES_H
