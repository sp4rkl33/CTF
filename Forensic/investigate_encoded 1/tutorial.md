# Problem:
https://play.picoctf.org/practice/challenge/47?category=4&page=5

# Tag: 
Hard, Forensic

# Tutorial: (Still updating sowwy :<)
  - Decompile the file with IDA or Ghidra (I'll use IDA) and step inside main function:
```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // rdi
  int v5; // [rsp+10h] [rbp-10h] BYREF
  int v6; // [rsp+14h] [rbp-Ch]
  FILE *stream; // [rsp+18h] [rbp-8h]

  stream = fopen("flag.txt", "r");
  if ( !stream )
  {
    fwrite("./flag.txt not found\n", 1uLL, 21uLL, stderr);
    exit(1);
  }
  flag_size = 0;
  fseek(stream, 0LL, 2);
  flag_size = ftell(stream);
  fseek(stream, 0LL, 0);
  if ( flag_size > 65534 )
  {
    fwrite("Error, file bigger that 65535\n", 1uLL, 0x1EuLL, stderr);
    exit(1);
  }
  flag = malloc(flag_size);
  v6 = fread(flag, 1uLL, flag_size, stream);
  if ( v6 <= 0 )
    exit(0);
  v5 = 0;
  flag_index = (__int64)&v5;
  output = fopen("output", "w");
  buffChar = 0;
  remain = 7;
  v3 = stream;
  fclose(stream);
  encode(v3);
  fclose(output);
  fwrite("I'm Done, check ./output\n", 1uLL, 0x19uLL, stderr);
  return 0;
}
```
  - At first glance the program recieve the flag then it encrypt the flag and store it into output file
  - Let's step into encode():
```C
__int64 encode()
{
  __int64 result; // rax
  unsigned int Value; // [rsp+0h] [rbp-10h]
  int v2; // [rsp+4h] [rbp-Ch]
  unsigned int v3; // [rsp+8h] [rbp-8h]
  char v4; // [rsp+Fh] [rbp-1h]
  char v5; // [rsp+Fh] [rbp-1h]

  while ( *(_DWORD *)flag_index < flag_size )
  {
    v4 = *((_BYTE *)flag + *(int *)flag_index);
    if ( (unsigned __int8)isValid((unsigned int)v4) != 1 )
    {
      fwrite("Error, I don't know why I crashed\n", 1uLL, 0x22uLL, stderr);
      exit(1);
    }
    v5 = lower((unsigned int)v4);
    if ( v5 == 32 )
      v5 = 123;
    v3 = dword_DC4[2 * v5 - 194];
    v2 = *((_DWORD *)&matrix + 2 * v5 - 194) + v3;
    while ( (int)v3 < v2 )
    {
      Value = getValue(v3);
      save(Value);
      ++v3;
    }
    ++*(_DWORD *)flag_index;
  }
  while ( 1 )
  {
    result = (unsigned int)remain;
    if ( remain == 7 )
      break;
    save(0LL);
  }
  return result;
}
```
