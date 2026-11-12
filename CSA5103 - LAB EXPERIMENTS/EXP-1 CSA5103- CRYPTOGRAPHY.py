
text = input("Enter plaintext: ")
key = int(input("Enter key (1-25): "))

if not 1 <= key <= 25:
    print("Invalid key! Enter a value from 1 to 25.")
else:
    result = ""

    for ch in text:
        if ch.isupper():
            result += chr((ord(ch) - ord('A') + key) % 26 + ord('A'))
        elif ch.islower():
            result += chr((ord(ch) - ord('a') + key) % 26 + ord('a'))
        else:
            result += ch

    print("Ciphertext:", result)
