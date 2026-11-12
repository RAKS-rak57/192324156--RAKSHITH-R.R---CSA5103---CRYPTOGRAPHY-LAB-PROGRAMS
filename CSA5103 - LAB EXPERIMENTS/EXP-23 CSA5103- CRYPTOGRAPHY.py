
# S-DES Counter (CTR) Mode

P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8 = [6, 3, 7, 4, 8, 5, 10, 9]
IP = [2, 6, 3, 1, 4, 8, 5, 7]
IPI = [4, 1, 3, 5, 7, 2, 8, 6]
EP = [4, 1, 2, 3, 2, 3, 4, 1]
P4 = [2, 4, 3, 1]

S0 = [[1,0,3,2], [3,2,1,0], [0,2,1,3], [3,1,3,2]]
S1 = [[0,1,2,3], [2,0,1,3], [3,0,1,0], [2,1,0,3]]

def permute(bits, table):
    return ''.join(bits[i-1] for i in table)

def xor(a, b):
    return ''.join(str(int(x) ^ int(y)) for x, y in zip(a, b))

def generate_keys(key):
    bits = permute(key, P10)
    left, right = bits[:5], bits[5:]
    left, right = left[1:] + left[:1], right[1:] + right[:1]
    k1 = permute(left + right, P8)
    left, right = left[2:] + left[:2], right[2:] + right[:2]
    k2 = permute(left + right, P8)
    return k1, k2

def fk(bits, key):
    left, right = bits[:4], bits[4:]
    expanded = xor(permute(right, EP), key)

    def sbox(value, box):
        row = int(value[0] + value[3], 2)
        col = int(value[1:3], 2)
        return format(box[row][col], '02b')

    result = sbox(expanded[:4], S0) + sbox(expanded[4:], S1)
    return xor(left, permute(result, P4)) + right

def encrypt(block, key):
    k1, k2 = generate_keys(key)
    bits = permute(block, IP)
    bits = fk(bits, k1)
    bits = bits[4:] + bits[:4]
    bits = fk(bits, k2)
    return permute(bits, IPI)

key = input("Enter 10-bit key: ").strip()
plaintext = input("Enter plaintext bits: ").replace(" ", "")

if (len(key) != 10 or set(key) - {'0', '1'}
    or not plaintext or len(plaintext) % 8 != 0
    or set(plaintext) - {'0', '1'}):
    print("Invalid input.")
else:
    blocks = [plaintext[i:i+8]
              for i in range(0, len(plaintext), 8)]

    ciphertext = []
    decrypted = []

    for count, block in enumerate(blocks):
        counter = format(count, '08b')
        stream = encrypt(counter, key)
        ciphertext.append(xor(block, stream))

    # CTR decryption uses the same counter and encryption operation
    for count, block in enumerate(ciphertext):
        counter = format(count, '08b')
        stream = encrypt(counter, key)
        decrypted.append(xor(block, stream))

    print("Ciphertext:", ' '.join(ciphertext))
    print("Decrypted:", ' '.join(decrypted))
