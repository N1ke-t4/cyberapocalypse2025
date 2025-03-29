# Summoners Incantation

## Challenge description

Deep within the ancient halls lies the secret of the Dragon's Heart—a power that can only be unlocked by combining magical tokens in just the right way. The tokens are delicate: if you combine two adjacent tokens, their energy dissipates into the void.

Your quest is to determine the maximum amount of energy that can be harnessed by selecting tokens such that no two selected tokens are adjacent. This challenge is equivalent to finding the maximum sum of non-adjacent numbers from a list.

### Input Format
A single line containing a Python-style list of integers representing token energies.

Example: [3, 2, 5, 10, 7]

### Output Format
A single integer that is the maximum energy obtainable by summing non-adjacent tokens.

### Example 1
Input:
```
[3, 2, 5, 10, 7]
```
Output:
```
15
```
Explanation: 

The optimal selection is to pick tokens 3, 5, and 7 (non-adjacent), yielding a sum of 3 + 5 + 7 = 15.

### Example 2
Input:
```
[10, 18, 4, 7]
```
Output:
```
25
```
Explanation: 

The best choice is to select 18 and 7 (tokens at positions 2 and 4) for a total of 18 + 7 = 25.

### Ancient Wisdom
Examine each token's energy value carefully.
If you combine adjacent tokens, their magical energy is lost!
Find the optimal combination that maximizes the total energy while ensuring no two tokens are adjacent.

## Solution

```python
# Input the text as a single string
input_text = input()  # Example: "shock;979;23"

# Write your solution below and make sure to encode the word correctly
def quest(input_text):
    input_list = eval(input_text)

    if len(input_list) == 0:
        return 0
    if len(input_list) == 1:
        return nums[0]

    include = 0  # max sum including the current element
    exclude = 0  # max sum excluding the current element

    for token in input_list:
        new_include = exclude + token
        exclude = max(include, exclude)
        include = new_include

    return max(include, exclude)

print(quest(input_text))
```

## Flag
```
HTB{SUMM0N3RS_INC4NT4T10N_R3S0LV3D_a9690689e4cda56f7f0c965a3c9cb246}
```
