
def create_matrix(keyword):
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    key = ""

    for ch in (keyword + alphabet).upper():
        if ch.isalpha():
            ch = 'I' if ch == 'J' else ch
            if ch not in key:
                key += ch

    return [list(key[i:i + 5]) for i in range(0, 25, 5)]


def prepare_text(text):
    text = ''.join(
        ch for ch in text.upper() if ch.isalpha()
    ).replace('J', 'I')

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

        pairs.append((a, b))

    return pairs


def encrypt(plaintext, keyword):
    matrix = create_matrix(keyword)
    positions = {
        matrix[r][c]: (r, c)
        for r in range(5) for c in range(5)
    }

    result = ""

    for a, b in prepare_text(plaintext):
        r1, c1 = positions[a]
        r2, c2 = positions[b]

        if r1 == r2:  # Same row
            result += matrix[r1][(c1 + 1) % 5]
            result += matrix[r2][(c2 + 1) % 5]
        elif c1 == c2:  # Same column
            result += matrix[(r1 + 1) % 5][c1]
            result += matrix[(r2 + 1) % 5][c2]
        else:  # Rectangle rule
            result += matrix[r1][c2]
            result += matrix[r2][c1]

    return result


text = input("Enter plaintext: ")
keyword = input("Enter keyword: ")

print("Ciphertext:", encrypt(text, keyword))
