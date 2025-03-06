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
secret_key = b'Africa!'

flag = encrypt(pxtx, random_strs[2])
flag = encrypt(flag, random_strs[3])
flag = encrypt(flag, random_strs[4])

print("{}".format(encrypt(flag, secret_key)))
