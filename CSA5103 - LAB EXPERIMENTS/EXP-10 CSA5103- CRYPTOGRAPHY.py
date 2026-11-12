
# Playfair Cipher Encryption using the given matrix

matrix = [
    ['M', 'F', 'H', 'I', 'K'],
    ['U', 'N', 'O', 'P', 'Q'],
    ['Z', 'V', 'W', 'X', 'Y'],
    ['E', 'L', 'A', 'R', 'G'],
    ['D', 'S', 'T', 'B', 'C']
]

# Store the position of each letter
position = {}

for r in range(5):
    for c in range(5):
        position[matrix[r][c]] = (r, c)

# I and J share the same cell
position['J'] = position['I']


def prepare_text(text):
    text = ''.join(ch for ch in text.upper() if ch.isalpha())
    text = text.replace('J', 'I')

    pairs = []
    i = 0

    while i < len(text):
        a = text[i]

        if i + 1 >= len(text):
            b = 'X'
            i += 1
        elif text[i] == text[i + 1]:
            b = 'X'
            i += 1
        else:
            b = text[i + 1]
            i += 2

        pairs.append(a + b)

    return pairs


def encrypt_pair(pair):
    a, b = pair
    r1, c1 = position[a]
    r2, c2 = position[b]

    if r1 == r2:
        # Same row: move right
        return matrix[r1][(c1 + 1) % 5] + \
               matrix[r2][(c2 + 1) % 5]

    elif c1 == c2:
        # Same column: move down
        return matrix[(r1 + 1) % 5][c1] + \
               matrix[(r2 + 1) % 5][c2]

    else:
        # Rectangle rule: exchange columns
        return matrix[r1][c2] + matrix[r2][c1]


# Get input from user
plaintext = input("Enter plaintext: ")

pairs = prepare_text(plaintext)
ciphertext = ""

for pair in pairs:
    ciphertext += encrypt_pair(pair)

print("\nPrepared letter pairs:")
print(" ".join(pairs))

print("\nEncrypted letter pairs:")
print(" ".join(
    encrypt_pair(pair) for pair in pairs
))

print("\nCiphertext:")
print(ciphertext)
