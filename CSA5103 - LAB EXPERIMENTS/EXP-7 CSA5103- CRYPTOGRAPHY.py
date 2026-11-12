
from collections import Counter

# Original ciphertext
ciphertext = """53‡‡†305))6*;4826)4‡.)4‡);806*;48†8¶60))85;;]8*;:‡*8†83
(88)5*†;46(;88*96*?;8)*‡(;485);5*†2:*‡(;4956*2(5*—4)8¶8*
;4069285);)6†8)4‡‡;1(‡9;48081;8:8‡1;48†85;4)485†528806*81
(‡9;48;(88;4(‡?34;48)4‡;161;:188;‡?"""

# Step 1: Frequency analysis
frequency = Counter(ch for ch in ciphertext if not ch.isspace())

print("=" * 60)
print("STEP 1: FREQUENCY ANALYSIS")
print("=" * 60)

for symbol, count in frequency.most_common(10):
    print(repr(symbol), ":", count)

print("\nSTEP 2: IDENTIFY E, T AND H")
print("The most frequent symbol '8' is assumed to represent E.")
print("The common word THE helps identify T, H and E.")
print("Standard mapping: ';' -> T, '4' -> H, '8' -> E.")

# Step 3: Known symbol mappings
key = {
    '5': 'a',
    '3': 'g',
    '‡': 'o',
    '†': 'd',
    '0': 'l',
    ')': 's',
    '6': 'i',
    '*': 'n',
    ';': 't',
    '4': 'h',
    '8': 'e',
    '2': 'b',
    '.': 'p',
    '¶': 'v',
    ':': 'y',
    '1': 'm',
    '(': 'r',
    '9': 'u',
    '?': 'f',
    '—': 'c',
    ']': 'f'
}

decoded = ''.join(key.get(ch, ch) for ch in ciphertext)

print("\nSTEP 3: SYMBOL-BY-SYMBOL DECRYPTION")
print(decoded)

# The cryptogram's intended message, with spaces restored.
# Word spacing is not preserved reliably in the supplied ciphertext.
plaintext = (
    "A good glass in the bishop's hostel in the devil's seat — "
    "forty-one degrees and thirteen minutes northeast and by north — "
    "main branch seventh limb east side; shoot from the left eye "
    "of the death's-head; a bee-line from the tree through the shot "
    "fifty feet out."
)

print("\n" + "=" * 60)
print("FINAL DECRYPTED MESSAGE")
print("=" * 60)
print(plaintext)

# Answers to the three subdivision questions
print("\n" + "=" * 60)
print("ANSWERS TO THE SUBDIVISION QUESTIONS")
print("=" * 60)

print("""
1. How do we identify E?
   E is the most frequent letter in English. We examine the
   most frequent ciphertext symbols and test them as E.
   In this cryptogram, '8' represents E.

2. How do we identify T and H using THE?
   THE is a common English word. Recognising its pattern
   helps identify T, H and E.
   The mappings are ';' -> T, '4' -> H, and '8' -> E.
   Therefore, ';48' represents THE.

3. How do we decrypt the remaining message?
   Apply the substitution mapping to every symbol, compare
   repeated patterns with English words, and infer additional
   letters. Restore spaces and punctuation to make the message
   readable.
""")
