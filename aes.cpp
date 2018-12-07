#include "aes.h"

AES::AES(){

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
    data[7] = tempChar;
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
