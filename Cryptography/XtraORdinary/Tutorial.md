# Problem
https://play.picoctf.org/practice/challenge/208?category=2&difficulty=3&page=2

# Description
Check out my new, never-before-seen method of encryption! I totally invented it myself. I added so many for loops that I don't even know what it does. It's extraordinarily secure! [output.txt](https://artifacts.picoctf.net/picoMini+by+redpwn/Cryptography/xtraordinary/output.txt) [encrypt.py](https://artifacts.picoctf.net/picoMini+by+redpwn/Cryptography/xtraordinary/encrypt.py)

# Tutorial
  - Suppose our expression like this:
```
V ^ secret_key ^ A ^ B ^ C ^ D ^ E
  - V is our flag
  - A, B, C, D, E is 5 strings in random_strs array.
```
  - We consider V is xor with a k-permutation of our random_strs and a secret_key (this is a constanst)
  - So we just need to loop thourgh all k-permutation of keys with (1 <= k <= 5) and our time complexity is ~~ O(1)
  - After perfrom XOR though a partial permutation of those string then we gonna try to guess the secret_key by XOR it this chunk "picoCTF{"
  - I've written to try all possible cases and here is it:
```py
def encrypt(ptxt, key):
    ctxt = b''
    for i in range(len(ptxt)):
        a = ptxt[i]
        b = key[i % len(key)]
        ctxt += bytes([a ^ b])
    return ctxt

random_strs = [
    b'my encryption method',
    b'is absolutely impenetrable',
    b'and you will never',
    b'ever',
    b'break it'
]

pxtx = bytes.fromhex("57657535570c1e1c612b3468106a18492140662d2f5967442a2960684d28017931617b1f3637")

permu = []

def saved(cur):
    arr = []
    mask = [0] * 6
    for i in cur:
        t = ord(i) - ord('0')
        if (mask[t] == 0):
            arr.append(t)
            mask[t] = 1
    permu.append(arr)

def recur(d, p, cur):
    if (d == 6): return

    for i in range(p, 6):
        recur(d + 1, i + 1, cur + chr(ord('0') + i))
        saved(cur + chr(ord('0') + i))

recur(1, 1, '')

for i in permu:
    tst = pxtx
    for ki in i:
        tst = encrypt(tst, random_strs[ki - 1])
    print("{}, {}".format(i, encrypt(tst[:8], b'picoCTF{')))
```
```
.
.
.
[2, 5], b',\rSZ\x1d\x0b^\x7f'
[2], b'N\x7f6;v+7\x0b'
[3, 4, 5], b'Africa!A' <= here is it hehehehe
[3, 4], b'#\x14\x17\x08\x08AH5'
[3, 5], b'$\x10\x17\x1b\x06\x17D3'
.
.
.
```
  - I've try to use b'Africa!A' but it seem not right so i guess that last 'A' is the key repeation so i changed it to b'Africa!' and got the right flag
```
  - flag: picoCTF{w41t_s[REACTED]}
```
