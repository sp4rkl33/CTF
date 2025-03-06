# Problem
https://play.picoctf.org/practice/challenge/114?category=2&difficulty=3&page=2

# Description
Not all ancient ciphers were so bad... The flag is not in standard format. nc mercury.picoctf.net 30568 [playfair.py](https://mercury.picoctf.net/static/9e655bebf3ad245e74ce5ca3a8352af1/playfair.py)

# Tutorial:
  - The netcat server return this:
```kali
┌──(kali㉿kali)-[~]
└─$ nc mercury.picoctf.net 30568
Here is the alphabet: 0fkdwu6rp8zvsnlj3iytxmeh72ca9bg5o41q
Here is the encrypted message: herfayo7oqxrz7jwxx15ie20p40u1i
What is the plaintext message? ^C
```

  - By looking at the name let's re-create our script to decrypt the following message:
```python
SQUARE_SIZE = 6

def generate_square(alphabet):
	assert len(alphabet) == pow(SQUARE_SIZE, 2)
	matrix = []
	for i, letter in enumerate(alphabet):
		if i % SQUARE_SIZE == 0:
			row = []
		row.append(letter)
		if i % SQUARE_SIZE == (SQUARE_SIZE - 1):
			matrix.append(row)
	return matrix

def get_index(letter, matrix):
	for row in range(SQUARE_SIZE):
		for col in range(SQUARE_SIZE):
			if matrix[row][col] == letter:
				return (row, col)
	print("letter not found in matrix.")
	exit()

def decrypt_pair(pair, matrix):
	p1 = get_index(pair[0], matrix)
	p2 = get_index(pair[1], matrix)
	if p1[0] == p2[0]: #If 2 character on the same row
		return matrix[p1[0]][(p1[1] - 1) % SQUARE_SIZE] + matrix[p2[0]][(p2[1] - 1)  % SQUARE_SIZE]
	elif p1[1] == p2[1]: #If 2 character on the same col
		return matrix[(p1[0] - 1)  % SQUARE_SIZE][p1[1]] + matrix[(p2[0] - 1) % SQUARE_SIZE][p2[1]]
	else: #If 2 character form a regtangle
		return matrix[p1[0]][p2[1]] + matrix[p2[0]][p1[1]]
	
def decrypt_string(s, matrix):
	result = ""
	for i in range(0, len(s), 2):
		result += decrypt_pair(s[i:i + 2], matrix)
	return result

alphabet = "0fkdwu6rp8zvsnlj3iytxmeh72ca9bg5o41q"
enc = "herfayo7oqxrz7jwxx15ie20p40u1i"
m = generate_square(alphabet)
print("matrix: ")
for i in m:
	print(i)

print("plain: ", decrypt_string(enc, m))
```
  - Our plaintext
```
emf57mgc51tp693dtt4g3h7f8ouwq3
```
  - Let's put it into the server then get our flag:
```kali
┌──(kali㉿kali)-[~]
└─$ nc mercury.picoctf.net 30568
Here is the alphabet: 0fkdwu6rp8zvsnlj3iytxmeh72ca9bg5o41q
Here is the encrypted message: herfayo7oqxrz7jwxx15ie20p40u1i
What is the plaintext message? emf57mgc51tp693dtt4g3h7f8ouwq3
Congratulations! Here's the flag: {REACTED}
```
```
