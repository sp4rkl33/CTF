#include <bits/stdc++.h>

using namespace std;

unsigned char matrix[] = {
  0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00,
  0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00,
  0x14, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x22, 0x00,
  0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00,
  0x0c, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x0c, 0x00,
  0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00,
  0x48, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x52, 0x00,
  0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00,
  0x0c, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x0c, 0x00,
  0x00, 0x00, 0x74, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00,
  0x80, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x8a, 0x00,
  0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x92, 0x00, 0x00, 0x00,
  0x0e, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x10, 0x00,
  0x00, 0x00, 0xae, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00,
  0xbe, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xc8, 0x00,
  0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00,
  0x0a, 0x00, 0x00, 0x00, 0xd6, 0x00, 0x00, 0x00, 0x0c, 0x00,
  0x00, 0x00, 0xe0, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00,
  0xec, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0xf8, 0x00,
  0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x06, 0x01, 0x00, 0x00,
  0x0e, 0x00, 0x00, 0x00, 0x16, 0x01, 0x00, 0x00, 0x04, 0x00,
  0x00, 0x00, 0x24, 0x01, 0x00, 0x00
};

unsigned char secret[] = {
  0xb8, 0xea, 0x8e, 0xba, 0x3a, 0x88, 0xae, 0x8e, 0xe8, 0xaa,
  0x28, 0xbb, 0xb8, 0xeb, 0x8b, 0xa8, 0xee, 0x3a, 0x3b, 0xb8,
  0xbb, 0xa3, 0xba, 0xe2, 0xe8, 0xa8, 0xe2, 0xb8, 0xab, 0x8b,
  0xb8, 0xea, 0xe3, 0xae, 0xe3, 0xba, 0x80
};

unsigned int getValue(int a){
    int iVar1 = a;
    if (a < 0){
        iVar1 = a + 7;
    }
    return (unsigned int)(unsigned char)secret[iVar1 >> 3] >> (7U - (char)(a % 8) & 31) & 1;
}

int main(){
    string abet = "abcdefghijklmnopqrstuvwxyz{";
    for (auto c : abet){ 
        string it = "";
        cout << (c == '{' ? ' ':c) << ' ';
        int st = *(int *)(matrix + (long)(c + -97) * 8 + 4);
        int ed = st + *(int *)(matrix + (long)(c + -97) * 8);
        for (; st < ed; st++){
            int uVar4 = getValue(st);
            cout << uVar4;
        }
        cout << '\n';
    }
    return 0;
}
