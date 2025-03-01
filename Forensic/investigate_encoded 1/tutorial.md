# Problem:
https://play.picoctf.org/practice/challenge/47?category=4&page=5

# Tag: 
Hard, Forensic

# Tutorial: (Still updating sowwy :<)
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
  - Checking the output file I know that it only 22 bytes but dose it match with the length of our input ?.
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
  - This perform some kind of crazy bit manipulation. Throw it into save():
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
  - Conclusion it a subtitiution cipher with each character is a bit string. By that we just write a script to create our bit-alphabet.
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
```C++

```
