# Problem:
https://play.picoctf.org/practice/challenge/47?category=4&page=5

# Decription:
We have recovered a [binary](https://jupiter.challenges.picoctf.org/static/e3904a8bf9fc321ffbe9360271067ecd/mystery) and 1 file: [image01](https://jupiter.challenges.picoctf.org/static/e3904a8bf9fc321ffbe9360271067ecd/output). See what you can make of it. NOTE: The flag is not in the normal picoCTF{XXX} format.

# Tag: 
Hard, Forensic

# Tutorial: 
  - Decompile the file with IDA or Ghidra (I'll use ghidra for this) and step inside main function:
```C
undefined8 main(void){
  long lVar1;
  size_t sVar2;
  undefined4 local_18;
  int local_14;
  FILE *local_10;
  
  local_10 = fopen("flag.txt","r");
  if (local_10 == (FILE *)0x0) {
    fwrite("./flag.txt not found\n",1,0x15,stderr);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  flag_size = 0;
  fseek(local_10,0,2);
  lVar1 = ftell(local_10);
  flag_size = (int)lVar1;
  fseek(local_10,0,0);
  if (0xfffe < flag_size) {
    fwrite("Error, file bigger that 65535\n",1,0x1e,stderr);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  flag = malloc((long)flag_size);
  sVar2 = fread(flag,1,(long)flag_size,local_10);
  local_14 = (int)sVar2;
  if (local_14 < 1) {
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  local_18 = 0;
  flag_index = &local_18;
  output = fopen("output","w");
  buffChar = 0;
  remain = 7;
  fclose(local_10);
  encode();
  fclose(output);
  fwrite("I\'m Done, check ./output\n",1,0x19,stderr);
  return 0;
}
```
  - At first glance the program receive the flag then it encrypt the flag and store it into output file
  - Let's step into encode():
```C
void encode(void){
  char cVar1;
  char cVar2;
  int iVar3;
  undefined4 uVar4;
  int local_10;
  char local_9;
  
  while( true ) {
    if (flag_size <= *flag_index) {
      while (remain != 7) {
        save(0);
      }
      return;
    }
    cVar1 = *(char *)(*flag_index + flag);
    cVar2 = isValid((int)cVar1);
    if (cVar2 != '\x01') break;
    local_9 = lower((int)cVar1);
    if (local_9 == ' ') {
      local_9 = '{';
    }
    local_10 = *(int *)(matrix + (long)(local_9 + -97) * 8 + 4);
    iVar3 = local_10 + *(int *)(matrix + (long)(local_9 + -97) * 8);
    for (; local_10 < iVar3; local_10 = local_10 + 1) {
      uVar4 = getValue(local_10);
      save(uVar4);
    }
    *flag_index = *flag_index + 1;
  }
  fwrite("Error, I don\'t know why I crashed\n",1,0x22,stderr);
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```
  - Look through everything we have here. This program will recieve our flag in the text file then by some kind of encryption method it encrypt the flag then put it in a text file.
  - The output text file may not present in unicode format.
  - First let's take a look at isValid().
```C
undefined8 isValid(char param_1){
  undefined8 uVar1;
  
  if ((param_1 < 'a') || ('z' < param_1)) {
    if ((param_1 < 'A') || ('Z' < param_1)) {
      if (param_1 == ' ') {
        uVar1 = 1;
      }
      else {
        uVar1 = 0;
      }
    }
    else {
      uVar1 = 1;
    }
  }
  else {
    uVar1 = 1;
  }
  return uVar1;
}
```
  - The program will only accept alphabet character and a space character.
  - Checking the output file I know that it only 22 bytes but does it match with the length of our input ?.
![alt text](https://github.com/sp4rkl33/CTF/blob/main/Forensic/investigate_encoded%201/Unti111tled.png)
  - Let's test for somecases
```terminal
┌──(kali㉿kali)-[~/Downloads/investigate_encoded1]
└─$ echo -n picoCTFthing > flag.txt 
                                                                             
┌──(kali㉿kali)-[~/Downloads/investigate_encoded1]
└─$ ./mystery
I'm Done, check ./output
                                                                             
┌──(kali㉿kali)-[~/Downloads/investigate_encoded1]
└─$ xxd -g 1 output 
00000000: bb a2 8e ba 3b b8 eb a3 8a e8 e2 a8 a3 a3 ba 00  ....;...........
```
  - As we can see the output is slightly longer than our input (3 bytes plus a null). This is a bad signal because it not a normal subtitiution cipher.
  - Take a look at the encryption part
```C
 while( true ) {
    if (flag_size <= *flag_index) {
      while (remain != 7) {
        save(0);
      }
      return;
    }
    cVar1 = *(char *)(*flag_index + flag);
    cVar2 = isValid((int)cVar1);
    if (cVar2 != '\x01') break;
    local_9 = lower((int)cVar1);
    if (local_9 == ' ') {
      local_9 = '{';
    }
    local_10 = *(int *)(matrix + (long)(local_9 + -97) * 8 + 4);
    iVar3 = local_10 + *(int *)(matrix + (long)(local_9 + -97) * 8);
    for (; local_10 < iVar3; local_10 = local_10 + 1) {
      uVar4 = getValue(local_10);
      save(uVar4);
    }
    *flag_index = *flag_index + 1;
  }
```
  - Firstly it checking the character is valid or not then lowercase it. This let us know that the flag is just a bunch of lowercase character and a space also.
  - Keep dive into the program.
  - getValue()
```C
uint getValue(int param_1){
  int iVar1;
  
  iVar1 = param_1;
  if (param_1 < 0) {
    iVar1 = param_1 + 7;
  }
  return (int)(uint)(byte)secret[iVar1 >> 3] >> (7U - (char)(param_1 % 8) & 31) & 1;
}
```
  - This perform some kind of crazy bit manipulation then it return right-most bit. Then throw it into save():
```C
void save(byte param_1){
  buffChar = buffChar | param_1;
  if (remain == 0) {
    remain = 7;
    fputc((int)(char)buffChar,output);
    buffChar = '\0';
  }
  else {
    buffChar = buffChar * 2; //buffChar <<= 1
    remain = remain + -1;
  }
  return;
}
```
  - buffChar look like a bit string. The function check if buffChar has exactly a byte then put it into the file (noticed that buffChar is a global variable)
```C
 if (flag_size <= *flag_index) {
      while (remain != 7) {
        save(0);
      }
      return;
    }
```
  - Then when the flag end it pad the rest bit into buffChar to form the last byte and put it into the output file

  - Now we have already understand the flow let try to encrypt small string. I choose "ee"
```terminal
┌──(kali㉿kali)-[~/Downloads/investigate_encoded1]
└─$ echo -n ee > flag.txt
                                                                             
┌──(kali㉿kali)-[~/Downloads/investigate_encoded1]
└─$ ./mystery            
I'm Done, check ./output
                                                                             
┌──(kali㉿kali)-[~/Downloads/investigate_encoded1]
└─$ xxd -g 1 output      
00000000: 88                                               .                            .
```
  - The byte we recieve is 0x88 which is very strange.
  - Let try with longer string like "efef"
```terminal
┌──(kali㉿kali)-[~/Downloads/investigate_encoded1]
└─$ echo -n efef > flag.txt
                                                                             
┌──(kali㉿kali)-[~/Downloads/investigate_encoded1]
└─$ ./mystery
I'm Done, check ./output
                                                                             
┌──(kali㉿kali)-[~/Downloads/investigate_encoded1]
└─$ xxd -g 1 output
00000000: 8a e8 8a e8                                      ....
```
  - The bytes we've recieved is 0x8ae88ae8 which repeatitive. Let's transfer everything to a bit string included the 0x8
```
0x8ae88ae8 = 0b10001010111010001000101011101000
0x8 = 0b1000
```
  - Take a closer look if we seperate it like this
```
0x8 - ae8 - 8 - ae8 = 0b1000 - 101011101000 - 1000 - 101011101000
                    =    e   -       f      -  e   -       f
```
  - Let perfome a test with only a character f
```terminal
┌──(kali㉿kali)-[~/Downloads/investigate_encoded1]
└─$ echo -n f > flag.txt   
                                                                             
┌──(kali㉿kali)-[~/Downloads/investigate_encoded1]
└─$ ./mystery 
I'm Done, check ./output
                                                                             
┌──(kali㉿kali)-[~/Downloads/investigate_encoded1]
└─$ xxd -g 1 output 
00000000: ae 80                                            ..
```
  - Bingo the bytes we got is 0xae80 but at we know earlier the program must form a byte then put into the output so it pad last 0x0 into the bytes.
  - Conclusion: It's a subtitiution cipher with each character is a bit string. By that we just write a script to create our bit-alphabet.
  - Before writing a script let's take a look at this part.
```C
    local_10 = *(int *)(matrix + (long)(local_9 + -97) * 8 + 4); //start
    iVar3 = local_10 + *(int *)(matrix + (long)(local_9 + -97) * 8); //end
    for (; local_10 < iVar3; local_10 = local_10 + 1) {
      uVar4 = getValue(local_10);
      save(uVar4);
    }
```
  - As we know different character will have different bit length. The result of local_10 and iVar3 will decided our length for the bit string.
  - Now just take out 2 array matrix and secret in the stack then write a script like this (we can treat matrix as a integer 1D-array).
```C
#include <bits/stdc++.h>

using namespace std;

int secret[37] = {0xb8, 0xea, 0x8e, 0xba, 0x3a, 0x88, 0xae, 0x8e, 0xe8, 0xaa, 0x28, 0xbb, 0xb8, 0xeb, 0x8b, 0xa8, 0xee, 0x3a, 0x3b, 0xb8, 0xbb, 0xa3, 0xba, 0xe2, 0xe8, 0xa8, 0xe2, 0xb8, 0xab, 0x8b, 0xb8, 0xea, 0xe3, 0xae, 0xe3, 0xba, 0x80};

int matrix[216] = {0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x52, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x58, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x74, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x8a, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x92, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0xae, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0xbe, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0xd0, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0xd6, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0xe0, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0xec, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0xf8, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x06, 0x01, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x16, 0x01, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x24, 0x01, 0x00, 0x00};

int buffChar = 0, remain = 0;

int getValue(int a){
    int iVar1 = a;
    if (a < 0){
        iVar1 = a + 7;
    }
    return (secret[iVar1 >> 3] >> (7 - (a % 8) & 31)) & 1;
}

int main(){
    string abet = "abcdefghijklmnopqrstuvwxyz{";
    for (auto c : abet){
        string it = "";
        int st = *(int *)(matrix + (long)(c - 97) * 8 + 4);
        int ed = st + *(int *)(matrix + (long)(c - 97) * 8);
        for (; st < ed; st++){
            int uVar4 = getValue(st);
            it = (char)(uVar4 + '0') + it;
        }
        cout << c << ' ' << it << endl;
    }
    return 0;
}
```
  - Run the script and get the our bit-alphabet:
```
a: 10111000
b: 111010101000
c: 11101011101000
d: 1110101000
e: 1000
f: 101011101000
g: 111011101000
h: 1010101000
i: 101000
j: 1011101110111000
k: 111010111000
l: 101110101000
m: 1110111000
n: 11101000
o: 11101110111000
p: 10111011101000
q: 1110111010111000
r: 1011101000
s: 10101000
t: 111000
u: 1010111000
v: 101010111000
w: 101110111000
x: 11101010111000
y: 1110101110111000
z: 11101110101000
 : 0000
```
  - Convert the content in the original output file to binary then match it with our bit-alphabet then summit.
  - My convert script
```python
f = open('output', 'rb')

enc = f.readline()

f.close()

abet = ['10111000', '111010101000', '11101011101000', '1110101000', '1000', '101011101000', '111011101000', '1010101000', '101000', '1011101110111000', '111010111000', '101110101000', '1110111000', '11101000', '11101110111000', '10111011101000', '1110111010111000', '1011101000', '10101000', '111000', '1010111000', '101010111000', '101110111000', '11101010111000', '1110101110111000', '11101110101000', '0000']

enc_flag = '{0:0b}'.format(int(enc.hex(), 16))

chunk = ''

flag = ''
while (len(chunk) < len(enc_flag)):
    no = 0
    for i in range(0, len(abet)):
        tmp = chunk + abet[i]
        if (tmp == enc_flag[:len(tmp)]):
            if (i == 26): flag += ' '
            else: flag += chr(97 + i)
            chunk += abet[i]
            no = 1
            break
    if (no == 0): break

print(flag)
```
```
10001110100011101011101000111011101110001110101000100011101010001010001110111000101010111000101110100010101010001011101110111000111010111000111010100011101110101000111010100000
- Flag: encode....
```
