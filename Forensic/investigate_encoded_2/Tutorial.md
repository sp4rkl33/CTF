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
