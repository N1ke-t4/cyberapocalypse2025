# Enchanted Cipher

## Challenge description

The Grand Arcane Codex has been corrupted, altering historical records. Each entry has been encoded with an enchanted shifting cipher that encrypts a plaintext composed of 3–7 randomly generated words.

The cipher operates as follows:

- Alphabetical characters are processed in groups of 5 (ignoring non-alphabetical characters).
- For each group, a random shift between 1 and 25 is chosen and applied to every letter in that group.
- After the encoded message, an additional line indicates the total number of shift groups, followed by another line listing the random shift values used for each group.

Your quest is to decode the given input and restore the original plaintext.

### Input Format
```
ibeqtsl
2
[4, 7]
```

### Output Format
```
example
```


## Solution

```python
import math

# Input the text as a single string
input_text = input()
input_shift_groups = input()
input_shift_values = input()

# Write your solution below and make sure to encode the word correctly
shift_values = eval(input_shift_values)

def quest(text, values):
    spaces = 0
    result = ""
    for i in range(len(input_text)):
        if input_text[i] == ' ':  # ignore whitespaces
            spaces += 1
            result += ' '
            continue
        shift_index = math.floor((i-spaces)/5)  # calculate shift value index
        newchar = chr((ord(input_text[i]) - shift_values[shift_index] - ord('a')) % 26 + ord('a'))  # decode character
        result += newchar
    return result

print(quest(input_text, shift_values))

```

## Test Example
#### Input Scroll
```
qlvl rzygss ibbp
3
[10, 18, 13]
```
#### Decoded Message
```
gblb hhgoaa vooc
```

## Flag

```
HTB{3NCH4NT3D_C1PH3R_D3C0D3D_4d9c51bf8365aaf04e152858a5c3c33c}
```
