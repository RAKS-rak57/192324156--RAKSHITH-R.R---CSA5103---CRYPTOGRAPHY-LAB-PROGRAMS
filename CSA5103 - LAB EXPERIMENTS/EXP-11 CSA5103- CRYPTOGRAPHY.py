
import math

total_keys = math.factorial(25)
total_power = math.log2(total_keys)

unique_keys = total_keys / 16
unique_power = math.log2(unique_keys)

print("Total possible keys: 25!")
print("Approximate total keys: 2^{:.2f}".format(total_power))

print("Effectively unique keys: 25! / 16")
print("Approximate unique keys: 2^{:.2f}".format(unique_power))
