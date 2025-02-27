# Problem:
https://play.picoctf.org/practice/challenge/79?category=3&page=6

# Description:
We have recovered a binary and a text file. Can you reverse the flag.

# Tutorial:
  - The text file give us a encoded ascii_text flag like this: <br>
```
picoCTF{w1{1wq84fb<1>49}
```
  - Open the binary file with ida or ghidra (I'll use ida). <br>
  - Decompile the file give us the main function like this:
``` C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE ptr[23]; // [rsp+0h] [rbp-50h] BYREF
  char v5; // [rsp+17h] [rbp-39h]
  int v6; // [rsp+2Ch] [rbp-24h]
  FILE *v7; // [rsp+30h] [rbp-20h]
  FILE *stream; // [rsp+38h] [rbp-18h]
  int j; // [rsp+44h] [rbp-Ch]
  int i; // [rsp+48h] [rbp-8h]
  char v11; // [rsp+4Fh] [rbp-1h]

  stream = fopen("flag.txt", "r");
  v7 = fopen("rev_this", "a");
  if ( !stream )
    puts("No flag found, please make sure this is run on the server");
  if ( !v7 )
    puts("please run this on the server");
  v6 = fread(ptr, 0x18uLL, 1uLL, stream);
  if ( v6 <= 0 )
    exit(0);
  for ( i = 0; i <= 7; ++i )
  {
    v11 = ptr[i];
    fputc(v11, v7);
  }
  for ( j = 8; j <= 22; ++j )
  {
    v11 = ptr[j];
    if ( (j & 1) != 0 )
      v11 -= 2;
    else
      v11 += 5;
    fputc(v11, v7);
  }
  v11 = v5;
  fputc(v5, v7);
  fclose(v7);
  return fclose(stream);
}
```
  - Based on the code we can easily see the program only encode 15 characters in 2 bracket {} so we gonna write a decrypt script based on the second for loop <br>
```c++
#include <bits/stdc++.h>

using namespace std;

int main(){
    freopen("rev_this", "r", stdin);
    char c[24]; for (auto &it:c) cin >> it;
    for (int i = 8; i <= 22; i++){
        if (i & 1) c[i] += 2;
        else c[i] -= 5;
    }

    for (int i = 0; i < 24; i++) cout << c[i];
    cout << '\n';
    return 0;
}
```
  - just run this script and we'll get the flag: 
  - flag: picoCTF{REACTED}
