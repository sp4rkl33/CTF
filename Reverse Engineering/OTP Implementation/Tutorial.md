# Problem:
https://play.picoctf.org/practice/challenge/92?category=3&page=6

# Descripstion:
Yay reversing! Relevant files: [otp](https://jupiter.challenges.picoctf.org/static/a2a15755ba8be4b4dabf60f8f35ec44e/otp) [flag.txt](https://jupiter.challenges.picoctf.org/static/a2a15755ba8be4b4dabf60f8f35ec44e/flag.txt)

# Tutorial:
  - Decompile with IDA or Ghidra (i used IDA) we obtain the main function like this:
```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char v4; // al
  char v5; // dl
  unsigned int v6; // eax
  int i; // [rsp+18h] [rbp-E8h]
  int j; // [rsp+1Ch] [rbp-E4h]
  char dest[112]; // [rsp+20h] [rbp-E0h] BYREF
  char s1[104]; // [rsp+90h] [rbp-70h] BYREF
  unsigned __int64 v11; // [rsp+F8h] [rbp-8h]

  v11 = __readfsqword(0x28u);
  if ( argc > 1 )
  {
    strncpy(dest, argv[1], 100uLL);
    dest[100] = 0;
    for ( i = 0; valid_char(dest[i]); ++i )
    {
      if ( i )
      {
        v4 = jumble(dest[i]);
        v5 = s1[i - 1] + v4;
        v6 = (unsigned int)((s1[i - 1] + v4) >> 31) >> 28;
        s1[i] = ((v6 + v5) & 0xF) - v6;
      }
      else
      {
        s1[0] = (char)jumble(dest[0]) % 16;
      }
    }
    for ( j = 0; j < i; ++j )
      s1[j] += 97;
    if ( i == 100
      && !strncmp(
            s1,
            "bajbgfapbcclgoejgpakmdilalpomfdlkngkhaljlcpkjgndlgmpdgmnmepfikanepopbapfkdgleilhkfgilgabldofbcaedgfe",
            100uLL) )
    {
      puts("You got the key, congrats! Now xor it with the flag!");
      return 0;
    }
    else
    {
      puts("Invalid key!");
      return 1;
    }
  }
  else
  {
    printf("USAGE: %s [KEY]\n", *argv);
    return 1;
  }
}
```
  - Look like the program is gonna recieve our input then encrypt it. Observing that at line 34 it compare out encrypt with some string.
  - If we manage to reverse the string or brute-force it we can get the plain-key then just xor it with the content in the text file we'll get the flag.
  - Before write a decryption script we have some function to look out:
```C
_BOOL8 __fastcall valid_char(char a1)
{
  if ( a1 > '/' && a1 <= '9' )
    return 1LL;
  return a1 > '`' && a1 <= 'f';
}
```
  - This function give us a very important info that out key will be a hex string.
```C
__int64 __fastcall jumble(char a1)
{
  char v2; // [rsp+0h] [rbp-4h]
  char v3; // [rsp+0h] [rbp-4h]

  v2 = a1;
  if ( a1 > 96 )
    v2 = a1 + 9;
  v3 = 2 * (v2 % 16);
  if ( v3 > 15 )
    ++v3;
  return (unsigned __int8)v3;
}
```
  - This maybe some kind of encryption.
  - Because the key length is just 100 and it's a hex string so we just brute-force for each character until we find the whole key
  - Our time complexity in number will be O(16 * 100) which is very small.
```C++
#include <bits/stdc++.h>

using namespace std;

int jumble(char a){
    int x, y;
    x = a;
    if (a > 96) x += 9;
    y = 2 * (x & 15);
    if (y > 15) ++y;
    return y;
}

char c[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

int main(){
    string enc = "bajbgfapbcclgoejgpakmdilalpomfdlkngkhaljlcpkjgndlgmpdgmnmepfikanepopbapfkdgleilhkfgilgabldofbcaedgfe", key(100, '0');
    
    //fine the first char
    for (auto it:c)
        if ((char)(jumble(it)) % 16 + 97 == 'b') {
            key[0] = char(jumble(it));
            cout << it; //print each char
            break;
        }

    //fine the rest key;
    for (int i = 1; i < 100; i++){
        for (auto it:c){
            int v4 = jumble(it), v5 = key[i - 1] + v4;
            if ((v5 & 15) + 97 == (int)enc[i]) {
                key[i] = v5 & 15;
                cout << it; //print each char
            }
        }
    }

    return 0;
}
```
  - Run this script get the key then just XOR with the hex string in the txt file to get the flag.
  - Flag: picoCTF{REACTED}
