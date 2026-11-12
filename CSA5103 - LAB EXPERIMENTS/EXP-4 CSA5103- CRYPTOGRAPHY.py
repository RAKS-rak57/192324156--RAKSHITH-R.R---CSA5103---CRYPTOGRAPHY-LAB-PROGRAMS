
text = input("Enter plaintext: ")
key = input("Enter keyword: ").upper()

if not key.isalpha():
    print("Invalid key! Use alphabetic characters only.")
else:
    result = ""
    key_index = 0

    for ch in text:
        if ch.isalpha():
            p = ord(ch.upper()) - ord('A')
            k = ord(key[key_index % len(key)]) - ord('A')

            c = (p + k) % 26
            encrypted = chr(c + ord('A'))

            result += encrypted if ch.isupper() else encrypted.lower()
            key_index += 1
        else:
            result += ch

    print("Ciphertext:", result)
