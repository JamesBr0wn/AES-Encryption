#include "configure.h"
#ifndef AES_H
#define AES_H

class AES{
public:
    AES();
    void ByteSub(std::bitset<8> data[16]);
    void RowShift(std::bitset<8> data[16]);
    void InvRowShift(std::bitset<8> data[16]);
    void InvByteSub(std::bitset<8> data[16]);
    void ColumnMix(std::bitset<8> data[16]);
    void InvColumnMix(std::bitset<8> data[16]);
    void RoundKeyAdd(std::bitset<8> data[16], std::bitset<8> key[16]);
};

#endif // AES_H
