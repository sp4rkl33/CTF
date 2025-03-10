#include <bits/stdc++.h>

using namespace std;

unsigned char index_table[] = { 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x52, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 0x8e, 0x00, 0x00, 0x00, 0x9e, 0x00, 0x00, 0x00, 0xb4, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0xda, 0x00, 0x00, 0x00, 0xea, 0x00, 0x00, 0x00, 0xfc, 0x00, 0x00, 0x00, 0x0e, 0x01, 0x00, 0x00, 0x1e, 0x01, 0x00, 0x00, 0x34, 0x01, 0x00, 0x00, 0x48, 0x01, 0x00, 0x00, 0x5a, 0x01, 0x00, 0x00, 0x6a, 0x01, 0x00, 0x00, 0x72, 0x01, 0x00, 0x00, 0x80, 0x01, 0x00, 0x00, 0x8c, 0x01, 0x00, 0x00, 0x9a, 0x01, 0x00, 0x00, 0xaa, 0x01, 0x00, 0x00, 0xbc, 0x01, 0x00, 0x00, 0xc8, 0x01, 0x00, 0x00, 0xd6, 0x01, 0x00, 0x00, 0xe0, 0x01, 0x00, 0x00, 0xea, 0x01, 0x00, 0x00, 0xf0, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x0a, 0x02, 0x00, 0x00, 0x16, 0x02, 0x00, 0x00, 0x22, 0x02, 0x00, 0x00, 0x30, 0x02, 0x00, 0x00, 0x34, 0x02, 0x00, 0x00 };

unsigned char secret[] = { 0x8b, 0xaa, 0x2e, 0xee, 0xe8, 0xbb, 0xae, 0x8e, 0xbb, 0xae, 0x3a, 0xee, 0x8e, 0xee, 0xa8, 0xee, 0xae, 0xe3, 0xaa, 0xe3, 0xae, 0xbb, 0x8b, 0xae, 0xb8, 0xea, 0xae, 0x2e, 0xba, 0x2e, 0xae, 0x8a, 0xee, 0xa3, 0xab, 0xa3, 0xbb, 0xbb, 0x8b, 0xbb, 0xb8, 0xae, 0xee, 0x2a, 0xee, 0x2e, 0x2a, 0xb8, 0xaa, 0x8e, 0xaa, 0x3b, 0xaa, 0x3b, 0xba, 0x8e, 0xa8, 0xeb, 0xa3, 0xa8, 0xaa, 0x28, 0xbb, 0xb8, 0xae, 0x2a, 0xe2, 0xee, 0x3a, 0xb8, 0x00 };

unsigned int getValue(int a){
    int iVar1 = a;
    if (a < 0) iVar1 += 7;
    return (int)(unsigned int)(unsigned char)secret[iVar1 >> 3] >> (7U - (char)(a % 8) & 0x1f) & 1;
}

int main(){
    string abet = "abcdefghijklmnopqrstuvwxyz0123456789 ";
    for (auto c : abet){
        cout << c << ": ";
        char tmp = c;
        bool badChars = 0;
        int iVar3, local_10;
        unsigned char bVar1;

        if (tmp == ' ') tmp = -0x7b;
        else if (('/' < tmp) && (tmp < ':')) tmp += 'K';
        
        tmp -= 0x61;

        if (tmp < '\0' || '$' < tmp) badChars = 1;

        if (tmp != '$'){
            iVar3 = (tmp + 0x12) % 0x24;
            bVar1 = (unsigned char)(iVar3 >> 0x1f);
            tmp = ((unsigned char)iVar3 ^ bVar1) - bVar1;
        }

        local_10 = *(int *)(index_table + (long)(int)tmp * 4);
        iVar3 = *(int *)(index_table + (long)(tmp + 1) * 4);
        for (; local_10 < iVar3; local_10++){
            cout << getValue(local_10);
        }
        cout << endl;
    }
}
