# Problem
https://play.picoctf.org/practice/challenge/36?category=4&difficulty=3&page=2
# Tag
Forensic, Hard.
# Description
We have recovered a [binary](https://jupiter.challenges.picoctf.org/static/c09444bcd3737284f3c046e700f2b7de/mystery) and 1 file: [image01](https://jupiter.challenges.picoctf.org/static/c09444bcd3737284f3c046e700f2b7de/output). See what you can make of it. NOTE: The flag is not in the normal picoCTF{XXX} format.
# Tutorial
  - Just like the last version step into encode()
```C
void encode(void){
  byte bVar1;
  undefined4 uVar2;
  int iVar3;
  int local_10;
  char local_9;
  
  while (*flag_index < flag_size) {
    local_9 = lower((int)*(char *)(*flag_index + flag));
    if (local_9 == ' ') {
      local_9 = -0x7b;
    }
    else if (('/' < local_9) && (local_9 < ':')) {
      local_9 = local_9 + 'K';
    }
    local_9 = local_9 + -0x61;
    if ((local_9 < '\0') || ('$' < local_9)) {
      badChars = 1;
    }
    if (local_9 != '$') {
      iVar3 = (local_9 + 0x12) % 0x24;
      bVar1 = (byte)(iVar3 >> 0x1f);
      local_9 = ((byte)iVar3 ^ bVar1) - bVar1;
    }
    iVar3 = *(int *)(indexTable + (long)(local_9 + 1) * 4);
    for (local_10 = *(int *)(indexTable + (long)(int)local_9 * 4); local_10 < iVar3;
        local_10 = local_10 + 1) {
      uVar2 = getValue(local_10);
      save(uVar2);
    }
    *flag_index = *flag_index + 1;
  }
  while (remain != 7) {
    save(0);
  }
  return;
}
```
  - Just by look at the for loop it still the same encryption method but we have some new bit manipulation operation.
  - To verify let step into getValue()
```C
uint getValue(int param_1){
  int iVar1;
  
  iVar1 = param_1;
  if (param_1 < 0) {
    iVar1 = param_1 + 7;
  }
  return (int)(uint)(byte)secret[iVar1 >> 3] >> (7U - (char)(param_1 % 8) & 0x1f) & 1;
}
```
  - With crazy bits manipulation the only purpos is to extract the rightmost bit then throw it into stack.
```C
void save(byte param_1){
  buffChar = buffChar | param_1;
  if (remain == 0) {
    remain = 7;
    fputc((int)(char)buffChar,output);
    buffChar = '\0';
  }
  else {
    buffChar = buffChar * '\x02';
    remain = remain + -1;
  }
  return;
}
```
  - Only give output when buffChar has enough 1 byte
  - Let's extract out index_table and secret arrays. Then write a script to get our bit alphabet.
```C++
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
```
  - Our bit-alphabet
```terminal
a: 101011101110111000
b: 1010101110111000
c: 10111000
d: 10101010111000
e: 101010101000
f: 11101010101000
g: 1110111010101000
h: 111011101110101000
i: 111010101000
j: 11101011101000
k: 1110101000
l: 1010101000
m: 101000
n: 1011101110111000
o: 1010111000
p: 101010111000
q: 101110111000
r: 11101010111000
s: 1000
t: 10111010101000
u: 1011101110111011101000
v: 10111011101011101000
w: 1110101110111010111000
x: 111010111011101000
y: 11101110111010101000
z: 1110111010101110111000
0: 1110101010111000
1: 1110101110101110111000
2: 10111010111010111000
3: 111010101010111000
4: 1011101011101000
5: 101110101011101000
6: 101011101110101000
7: 1110101011101000
8: 1110111011101110111000
9: 10111011101110111000
 : 0000
```
  - We can use old convert script to get our flag:
```py
f = open('output', 'rb')

enc = f.readline()

f.close()

abet = ['101011101110111000', '1010101110111000', '10111000', '10101010111000', '101010101000', '11101010101000', '1110111010101000', '111011101110101000', '111010101000', '11101011101000', '1110101000', '1010101000', '101000', '1011101110111000', '1010111000', '101010111000', '101110111000', '11101010111000', '1000', '10111010101000', '1011101110111011101000', '10111011101011101000', '1110101110111010111000', '111010111011101000', '11101110111010101000', '1110111010101110111000', '1110101010111000', '1110101110101110111000', '10111010111010111000', '111010101010111000', '1011101011101000', '101110101011101000', '101011101110101000', '1110101011101000', '1110111011101110111000', '10111011101110111000', '0000']

k = "abcdefghijklmnopqrstuvwxyz0123456789 ";

enc_flag = '{0:0b}'.format(int(enc.hex(), 16))

chunk = ''

flag = ''
while (len(chunk) < len(enc_flag)):
    no = 0
    for i in range(0, len(abet)):
        tmp = chunk + abet[i]
        if (tmp == enc_flag[:len(tmp)]):
            flag += k[i]
            chunk += abet[i]
            no = 1
            break
    if (no == 0): break

print(flag)

```
```
  - Original bit string: 10111010101000111010111010111011100010100011101010101011100011101010101000111010111010111011100011101010100011101010101011100010111010101110100011101010101110001110101010111000111010101011100011101010101110001110101010111000111010101011100011101010101110001110101010111000111010101011100011101010101110001110101010111000111010101010001011101110111011100010101010100010101010100011101011101011101110001110101110101110111000111011101110111011100011101010101110000000
  - Flag: t1m3f[REACTED}180
```
