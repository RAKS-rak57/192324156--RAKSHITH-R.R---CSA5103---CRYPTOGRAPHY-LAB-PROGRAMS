
# DES key schedule: generate all 16 round subkeys

PC1 = [
    57,49,41,33,25,17,9,1,58,50,42,34,26,18,
    10,2,59,51,43,35,27,19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,7,62,54,46,38,30,22,
    14,6,61,53,45,37,29,21,13,5,28,20,12,4
]

PC2 = [
    14,17,11,24,1,5,3,28,15,6,21,10,
    23,19,12,4,26,8,16,7,27,20,13,2,
    41,52,31,37,47,55,30,40,51,45,33,48,
    44,49,39,56,34,53,46,42,50,36,29,32
]

SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]

def permute(bits, table):
    return ''.join(bits[i - 1] for i in table)

def generate_subkeys(key_hex):
    key = bin(int(key_hex, 16))[2:].zfill(64)
    key56 = permute(key, PC1)

    c, d = key56[:28], key56[28:]
    subkeys = []

    for shift in SHIFTS:
        c = c[shift:] + c[:shift]
        d = d[shift:] + d[:shift]
        combined = c + d
        subkey = permute(combined, PC2)
        subkeys.append(hex(int(subkey, 2))[2:].upper().zfill(12))

    return subkeys

key_hex = input("Enter 16-digit DES key (hex): ").strip()

if len(key_hex) != 16:
    print("Error: DES key must contain 16 hexadecimal digits.")
else:
    try:
        int(key_hex, 16)
        keys = generate_subkeys(key_hex)

        for i, subkey in enumerate(keys, 1):
            print(f"K{i:02}: {subkey}")
    except ValueError:
        print("Error: Use hexadecimal digits only.")
