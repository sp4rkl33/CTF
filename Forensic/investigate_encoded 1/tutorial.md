# Problem:
https://play.picoctf.org/practice/challenge/47?category=4&page=5

# Tag: 
Hard, Forensic

# Tutorial: (Still updating sowwy :<)
  - Decompile the file with IDA or Ghidra (I'll use ghidra for this) and step inside main function:
```C
undefined8 main(void)

{
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
  - At first glance the program recieve the flag then it encrypt the flag and store it into output file
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
- Now we have 2 ways to solve this by brute-force the flag or reverse the encoded flag.
- First let's take a look at isValid().
```C
undefined8 isValid(char param_1)

{
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
  - This gave us a very important information that our flag will only be alphabets and a space character and the maximum character we have is 65 included uppercases and lowercases.
  - Checking the output file I know that it only 22 bytes 
![alt text](https://github.com/sp4rkl33/CTF/blob/main/Forensic/investigate_encoded%201/Unti111tled.png)
