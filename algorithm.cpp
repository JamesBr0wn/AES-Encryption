#include "algorithm.h"

AES::AES(EncryptType type){
    // 根据类型确定密钥长度
    switch(type){
        case AES128: // AES 128
            keyLength = 4;
            roundNum = 10;
            break;
        case AES192: // AES 192
            keyLength = 6;
            roundNum = 12;
            break;
        case AES256: // AES 256
            keyLength = 8;
            roundNum = 14;
            break;
    }
    keyPtr = new std::bitset<8>[4 * keyLength];
    expendedKeyPtr= new std::bitset<32>[4*(roundNum+1)];
}

AES::~AES(){
    // 释放申请的内存
    delete[] keyPtr;
    delete[] expendedKeyPtr;
}

void AES::SetKey(std::bitset<8>* key){
    // 设置初始密钥
    for(int i = 0; i < 4 * keyLength; i++){
        keyPtr[i] = key[i];
    }
    // 设置扩展密钥
    KeyExpend(keyPtr, expendedKeyPtr);
}

void AES::ByteSub(std::bitset<8> data[16]){
    int row, col;
    for(int i = 0; i < 16; i++){
        // 计算行号和列号，使用S盒进行字节代替变换
        row = data[i][7] * 8 + data[i][6] * 4 + data[i][5] * 2 + data[i][4];
        col = data[i][3] * 8 + data[i][2] * 4 + data[i][1] * 2 + data[i][0];
        data[i] = S_BOX[row][col];
    }
}

void AES::InvByteSub(std::bitset<8> data[16]){
    int row, col;
    for(int i = 0; i < 16; i++){
        // 计算行号和列号，使用逆S盒进行逆字节代替变换
        row = data[i][7] * 8 + data[i][6] * 4 + data[i][5] * 2 + data[i][4];
        col = data[i][3] * 8 + data[i][2] * 4 + data[i][1] * 2 + data[i][0];
        data[i] = INV_S_BOX[row][col];
    }
}

void AES::RowShift(std::bitset<8> data[16]){
    std::bitset<8> tempChar;

    // 第2行循环左移一个字符
    tempChar = data[4];
    for(int i = 0; i < 3; i++){
        data[i+4] = data[i+5];
    }
    data[7] = tempChar;

    // 第3行循环左移两个字符
    for(int i = 0; i < 2; i++){
        tempChar = data[i+8];
        data[i+8] = data[i+10];
        data[i+10] = tempChar;

    }

    // 第4行循环左移三个字符/循环右移一个字符
    tempChar = data[15];
    for(int i = 3; i > 0; i--){
        data[i+12] = data[i+11];
    }
    data[12] = tempChar;
}

void AES::InvRowShift(std::bitset<8> data[16]){
    std::bitset<8> tempChar;

    // 第2行循环右移一个字符
    tempChar = data[7];
    for(int i = 3; i > 0; i--){
        data[i+4] = data[i+3];
    }
    data[4] = tempChar;

    // 第3行循环右移两个字符
    for(int i = 0; i < 2; i++){
        tempChar = data[i+8];
        data[i+8] = data[i+10];
        data[i+10] = tempChar;

    }

    // 第4行循环右移三个字符/循环左移一个字符
    tempChar = data[12];
    for(int i = 0; i < 3; i++){
        data[i+12] = data[i+13];
    }
    data[15] = tempChar;
}

void AES::ColumnMix(std::bitset<8> data[16]){
    std::bitset<8> temp[4];
    for(int i = 0; i < 4; i++){
        // 获取对应列的元素
        for(int j = 0; j < 4; j++){
            temp[j] = data[i + j * 4];
        }

        // 计算乘积矩阵的一列
        data[i] = GFMul_0x02[temp[0].to_ulong()] ^ GFMul_0x03[temp[1].to_ulong()] ^ temp[2] ^ temp[3];
        data[i+4] = temp[0] ^ GFMul_0x02[temp[1].to_ulong()] ^ GFMul_0x03[temp[2].to_ulong()] ^ temp[3];
        data[i+8] = temp[0] ^ temp[1] ^ GFMul_0x02[temp[2].to_ulong()]  ^ GFMul_0x03[temp[3].to_ulong()];
        data[i+12] = GFMul_0x03[temp[0].to_ulong()] ^ temp[1] ^ temp[2] ^ GFMul_0x02[temp[3].to_ulong()];
    }
}

void AES::InvColumnMix(std::bitset<8> data[16]){
    std::bitset<8> temp[4];
    for(int i = 0; i < 4; i++){
        // 获取对应列的元素
        for(int j = 0; j < 4; j++){
            temp[j] = data[i + j * 4];
        }

        // 计算乘积矩阵的一列
        data[i] = GFMul_0x0e[temp[0].to_ulong()] ^ GFMul_0x0b[temp[1].to_ulong()] ^ GFMul_0x0d[temp[2].to_ulong()] ^ GFMul_0x09[temp[3].to_ulong()];
        data[i+4] = GFMul_0x09[temp[0].to_ulong()] ^ GFMul_0x0e[temp[1].to_ulong()] ^ GFMul_0x0b[temp[2].to_ulong()] ^ GFMul_0x0d[temp[3].to_ulong()];
        data[i+8] = GFMul_0x0d[temp[0].to_ulong()] ^ GFMul_0x09[temp[1].to_ulong()] ^ GFMul_0x0e[temp[2].to_ulong()] ^ GFMul_0x0b[temp[3].to_ulong()];
        data[i+12] = GFMul_0x0b[temp[0].to_ulong()] ^ GFMul_0x0d[temp[1].to_ulong()] ^ GFMul_0x09[temp[2].to_ulong()] ^ GFMul_0x0e[temp[3].to_ulong()];
    }
}

void AES::RoundKeyAdd(std::bitset<8> data[16], std::bitset<32> key[4]){
    for(int i = 0; i < 4; i++){
        for(int j = 0; j < 4; j++){
            // 明文一列中的4个字节与密钥中的1个字异或
            std::bitset<8> temp  = std::bitset<8>((key[i] << (static_cast<size_t>(j  * 8)) >> 24).to_ulong());
            data[i+j*4] ^= temp;
        }
    }
}

std::bitset<32> AES::WordGenerate(std::bitset<8> bytes[4]){
    // 将四个字节合并成一个字
    std::bitset<32> result = 0, temp;
    for(int i = 0; i < 4; i++){
        temp = bytes[i].to_ulong();
        temp <<= static_cast<size_t>(8 * (3-i));
        result |= temp;
    }
    return result;
}

std::bitset<32> AES::WordRot(std::bitset<32>& word){
    // 字以字节为单位左移
    return (word << 8) | (word >> 24);
}

std::bitset<32> AES::WordSub(std::bitset<32>& word){
    std::bitset<32> result;
    std::bitset<8> temp;
    for(int i = 0; i < 4; i++){
        // 字以字节为单位进行S盒替换
        int row = word[static_cast<size_t>(i*8+7)] * 8 + word[static_cast<size_t>(i*8+6)] * 4 + word[static_cast<size_t>(i*8+5)] * 2 + word[static_cast<size_t>(i*8+4)];
        int col = word[static_cast<size_t>(i*8+3)] * 8 + word[static_cast<size_t>(i*8+2)] * 4 + word[static_cast<size_t>(i*8+1)] * 2 + word[static_cast<size_t>(i*8)];
        temp = S_BOX[row][col];
        for(int j = 0; j < 8; j++){
            result[static_cast<size_t>(i*8+j)] = temp[static_cast<size_t>(j)];
        }
    }
    return result;
}

void AES::KeyExpend(std::bitset<8>* originKey, std::bitset<32>* expendedKey){
    std::bitset<32> temp;

    // 第一组轮密钥就是原始密钥
    for(int i = 0; i < keyLength; i++){
        expendedKey[i] = WordGenerate(&originKey[4*i]);
    }

    // 对于之后的轮密钥
    for(int i = keyLength; i < 4 * (roundNum + 1); i++){
        temp = expendedKey[i-1];

        if(i % keyLength == 0){
            // 每组轮密钥首个字处理后需要与轮常数异或
            temp = WordRot(temp);
            temp = WordSub(temp);
            expendedKey[i] = expendedKey[i-keyLength] ^ temp ^ ROUND_CONST[i/keyLength-1];
        }else{
            // 否则正常为上一个字异或上一轮对应字
            expendedKey[i] = expendedKey[i-keyLength] ^ temp;
        }
    }
}

void AES::Encrypt(std::bitset<8> data[16]){
    // 初始轮密钥加
    RoundKeyAdd(data, expendedKeyPtr);

    // 最后一轮外的每一轮
    for(int i = 1; i < roundNum; i++){
        ByteSub(data);      // 字节代替
        RowShift(data);     // 行移位
        ColumnMix(data);    // 列混淆
        RoundKeyAdd(data, expendedKeyPtr+4*i);  // 轮密钥加
    }

    // 最后一轮
    ByteSub(data);          // 字节代替
    RowShift(data);         // 行移位
    RoundKeyAdd(data, expendedKeyPtr+4*roundNum);// 轮密钥加
}

void AES::Decrypt(std::bitset<8> data[16]){
    // 初始轮密钥加
    RoundKeyAdd(data, expendedKeyPtr + 4 * roundNum);

    // 最后一轮外的每一轮
    for(int i = roundNum - 1; i > 0; i--){
        InvRowShift(data);  // 逆向行移位
        InvByteSub(data);   // 逆向字节代替
        RoundKeyAdd(data, expendedKeyPtr+4*i);  // 轮密钥加
        InvColumnMix(data); // 逆向列混淆
    }

    // 最后一轮
    InvRowShift(data);      // 逆向行移位
    InvByteSub(data);       // 逆向字节代替
    RoundKeyAdd(data, expendedKeyPtr);          // 轮密钥加
}

AESWrapper::AESWrapper(EncryptType type, WorkMode mode):aes(type){
    // 设置加密类型和工作模式
    this->type = type;
    this->mode = mode;
}

void AESWrapper::SetKey(std::string keyStr){
    // 设置加密密钥参数
    size_t keyLength = 0;
    std::bitset<8>* keyBin;
    switch(type){
        case AES128:
            keyLength = 16;
            break;
        case AES192:
        keyLength = 24;
            break;
        case AES256:
            keyLength = 32;
            break;
    }
    // 设置加密密钥，位数不足时使用0-Padding，位数超出时截断
    keyBin = new  std::bitset<8>[keyLength];
    for(size_t i =  0; i < keyLength; i++){
        if(i < keyStr.length()){
            keyBin[i] = static_cast<unsigned char>(keyStr[i]);
        }else{
            keyBin[i] = 0;
        }
    }
    aes.SetKey(keyBin);
    delete[] keyBin;
}

std::string AESWrapper::Encrypt(std::string dataStr){
    size_t dataLength = (dataStr.length()+15) / 16 * 16;
    std::bitset<8>* dataBin = new std::bitset<8>[dataLength];
    char low, high;
    std::string result;

    // 将字符串形式的明文转换为二进制类型，并进行补齐/截断
    for(size_t i = 0; i < dataLength; i++){
        if(i < dataStr.length()){
            dataBin[i] = static_cast<unsigned char>(dataStr[i]);
        }else{
            dataBin[i] = 0;
        }
    }

    // 根据不同的工作模式进行加密
    if(mode == ECB){    // 电码本模式
        for(size_t i = 0; i < dataLength/16; i++){
            aes.Encrypt(dataBin+i*16);
        }
    }else{              // 密文反馈模式
        std::bitset<8> temp[16];
        for(size_t i = 0; i < dataLength/16; i++){
            if(i > 0){
                for(size_t j = 0; j < 16; j++){
                    dataBin[i*16+j] ^= temp[j];
                }
            }
            aes.Encrypt(dataBin+i*16);
            for(size_t j = 0; j < 16; j++){
                temp[j] = dataBin[i*16+j];
            }
        }
    }

    for(size_t i = 0; i < dataLength; i++){
        high = static_cast<char>(dataBin[i].to_ulong() / 16);
        if(high > 9){
            high = high - 10 + 'A';
        }else{
            high = high + '0';
        }
        low = static_cast<char>(dataBin[i].to_ulong() % 16);
        if(low > 9){
            low = low - 10 + 'A';
        }else{
            low = low + '0';
        }
        result = result + high + low;
    }

    delete[] dataBin;
    return result;
}

std::string AESWrapper::Decrypt(std::string dataStr){
    size_t dataLength = dataStr.length() / 2;
    std::bitset<8>* dataBin = new std::bitset<8>[dataLength];
    int temp;
    std::string result;

    // 将字符串形式的密文转换为二进制类型，并进行补齐/截断
    for(size_t i = 0; i < dataLength; i++){
        if(isdigit(dataStr[2*i])){
            temp = dataStr[2*i] - '0';
        }else{
            temp = toupper(dataStr[2*i]) - 'A' + 10;
        }
        temp *= 16;
        if(isdigit(dataStr[2*i+1])){
            temp += dataStr[2*i+1] - '0';
        }else{
            temp += toupper(dataStr[2*i+1]) - 'A' + 10;
        }
        dataBin[i] = static_cast<unsigned long>(temp);
    }

    // 根据不同的工作模式进行解密
    if(mode == ECB){    // 电码本模式
        for(size_t i = 0; i < dataLength/16; i++){
            aes.Decrypt(dataBin+i*16);
        }
    }else{              // 密文反馈模式
        std::bitset<8> temp[2][16];
        for(size_t i = 0; i < dataLength/16; i++){
            for(size_t j = 0; j < 16; j++){
                temp[0][j] = dataBin[i*16+j];
            }
            aes.Decrypt(dataBin+i*16);
            if(i > 0){
                for(size_t j = 0; j < 16; j++){
                    dataBin[i*16+j] ^= temp[1][j];
                }
            }
            for(size_t j = 0; j < 16; j++){
                temp[1][j] = temp[0][j];
            }
        }
    }

    for(size_t i = 0; i < dataLength; i++){
        result = result + static_cast<char>(dataBin[i].to_ulong());
    }

    delete[] dataBin;
    return result;
}
