
def create_matrix(keyword):
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    sequence = ""

    for ch in (keyword.upper().replace("J", "I") + alphabet):
        if ch in alphabet and ch not in sequence:
            sequence += ch

    return [list(sequence[i:i + 5]) for i in range(0, 25, 5)]


def decrypt_playfair(ciphertext, keyword):
    matrix = create_matrix(keyword)

    positions = {
        matrix[r][c]: (r, c)
        for r in range(5)
        for c in range(5)
    }

    text = "".join(ch for ch in ciphertext.upper() if ch.isalpha())
    text = text.replace("J", "I")

    if len(text) % 2 != 0:
        raise ValueError("Ciphertext must contain an even number of letters.")

    plaintext = ""

    for i in range(0, len(text), 2):
        a, b = text[i], text[i + 1]

        # Special instruction given in the question
        if a == "T" and b == "T":
            plaintext += "tt"
            continue

        r1, c1 = positions[a]
        r2, c2 = positions[b]

        if r1 == r2:
            # Same row: move one position left
            plaintext += matrix[r1][(c1 - 1) % 5]
            plaintext += matrix[r2][(c2 - 1) % 5]

        elif c1 == c2:
            # Same column: move one position up
            plaintext += matrix[(r1 - 1) % 5][c1]
            plaintext += matrix[(r2 - 1) % 5][c2]

        else:
            # Rectangle rule: exchange columns
            plaintext += matrix[r1][c2]
            plaintext += matrix[r2][c1]

    return matrix, plaintext


keyword = input("Enter keyword: ")
print("Enter ciphertext (you can include spaces and newlines).")
print("Type END on a new line when finished:")

lines = []
while True:
    line = input()
    if line.strip().upper() == "END":
        break
    lines.append(line)

ciphertext = "\n".join(lines)

matrix, plaintext = decrypt_playfair(ciphertext, keyword)

print("\nPlayfair Matrix:")
for row in matrix:
    print(" ".join(row))

print("\nDecrypted plaintext:")
print(plaintext)

print("\nNote: Restore word spaces and punctuation manually.")
