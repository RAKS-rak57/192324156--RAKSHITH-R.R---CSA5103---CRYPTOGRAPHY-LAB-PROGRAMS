# SHA-3 sponge state analysis

STATE_SIZE = 1600
RATE = 1024
CAPACITY = STATE_SIZE - RATE
LANE_SIZE = 64

total_lanes = STATE_SIZE // LANE_SIZE
rate_lanes = RATE // LANE_SIZE
capacity_lanes = CAPACITY // LANE_SIZE

# Initialize all state lanes to zero
state = [0] * total_lanes

# First message block: each of its 16 lanes has a nonzero bit
P0 = [1] * rate_lanes

# XOR message block with the rate portion of the state
for i in range(rate_lanes):
    state[i] ^= P0[i]

# Count nonzero and zero lanes
nonzero = sum(1 for lane in state if lane != 0)
zero = total_lanes - nonzero

print("Total state bits:", STATE_SIZE)
print("Rate:", RATE)
print("Capacity:", CAPACITY)

print("\nTotal lanes:", total_lanes)
print("Rate lanes:", rate_lanes)
print("Capacity lanes:", capacity_lanes)

print("\nNonzero lanes after first block:", nonzero)
print("Remaining zero lanes:", zero)

print("\nTime required for all capacity lanes to become nonzero:")
print("Never (without permutation)")
