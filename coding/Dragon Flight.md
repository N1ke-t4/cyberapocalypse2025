# Dragon flight

Challenge description:

```
In the mystical realm of the Floating Isles, ancient dragons traverse the skies between floating sanctuaries. However, unpredictable winds now pose a dynamic threat!

As a Dragon Flight Master, your mission is to:

Handle both sudden wind changes and challenging flight path queries.
Process update operations that modify the wind effect on any flight segment.
Compute the maximum favorable continuous flight stretch (i.e., the maximum contiguous subarray sum) within a specified range.
Your precise calculations are critical to determine the safest and most efficient route for the dragons. Adapt quickly as wind conditions change, ensuring their journey remains uninterrupted.

Input Format Explanation
The input provided to the challenge is structured as follows:

First Line: Two space-separated integers, N and Q.
N represents the number of flight segments.
Q represents the number of operations to perform.
Second Line: N space-separated integers representing the initial net wind effects for each flight segment.
A positive value indicates a tailwind, which helps the dragon travel further.
A negative value indicates a headwind, which reduces the effective flight distance.
Next Q Lines: Each line represents an operation that can be one of the following:
U i x: An update operation where the wind effect on the i-th segment is changed to x.
Q l r: A query operation requesting the maximum contiguous subarray sum (i.e., the maximum net flight distance) for the segments in the range from l to r (inclusive).
Flight Example
Flight Path Input

6 6
-10 -7 -1 -4 0 -5
Q 3 3
U 2 9
Q 6 6
U 1 -1
Q 6 6
U 5 -9
    
Expected Output

-1
-5
-5
    
Explanation

# Step-by-Step Breakdown:

1. Initial Array:
   [-10, -7, -1, -4, 0, -5]
   - This array represents the wind effects for 6 flight segments.
   - Negative numbers indicate headwinds (reducing flight distance).

2. Operation 1: Q 3 3
   - Instruction: Query the subarray from index 3 to 3.
   - 1-indexed index 3 corresponds to the third element.
   - Extracted Subarray: [-1]
   - Maximum Contiguous Subarray Sum:
     Since there is only one element, the maximum sum is simply that element, -1.
   => Output: -1

3. Operation 2: U 2 9
   - Instruction: Update the element at index 2 to 9.
   - 1-indexed index 2 refers to the second element, which was originally -7.
   - Array Change: Replace -7 with 9.
   - New Array becomes: [-10, 9, -1, -4, 0, -5]
   - Note: Update operations do not produce any output.

4. Operation 3: Q 6 6
   - Instruction: Query the subarray from index 6 to 6.
   - 1-indexed index 6 corresponds to the sixth element.
   - Extracted Subarray: [-5]
   - Maximum Contiguous Subarray Sum:
     With only one element (-5), the result is -5.
   => Output: -5

5. Operation 4: U 1 -1
   - Instruction: Update the element at index 1 to -1.
   - 1-indexed index 1 refers to the first element, which was originally -10.
   - Array Change: Replace -10 with -1.
   - New Array becomes: [-1, 9, -1, -4, 0, -5]
   - Again, no output is produced for an update.

6. Operation 5: Q 6 6
   - Instruction: Query the subarray from index 6 to 6 again.
   - The sixth element is still -5.
   - Extracted Subarray: [-5]
   - Maximum Contiguous Subarray Sum remains -5.
   => Output: -5

7. Operation 6: U 5 -9
   - Instruction: Update the element at index 5 to -9.
   - 1-indexed index 5 refers to the fifth element, which was originally 0.
   - Array Change: Replace 0 with -9.
   - Final Array becomes: [-1, 9, -1, -4, -9, -5]
   - This operation is an update, so no output is generated.
```


```python
# Read input lines into variables.
input1 = input()  # e.g., "5 3" (number of segments and operations)
input2 = input()  # e.g., "10 -2 3 -1 5" (initial wind effects)

# Parse inputs
N, Q = map(int, input1.split())  # Number of segments (N) and operations (Q)
arr = list(map(int, input2.split()))  # Initial wind effects

# Read Q lines of operations dynamically
queries = [input().strip() for _ in range(Q)]

class SegmentTree:
    class Node:
        def __init__(self, value):
            self.total = value
            self.best_prefix = value
            self.best_suffix = value
            self.best_sum = value

    def __init__(self, arr):
        self.n = len(arr)
        self.tree = [None] * (4 * self.n)
        self.build(arr, 0, 0, self.n - 1)

    def build(self, arr, node, start, end):
        if start == end:
            self.tree[node] = self.Node(arr[start])
        else:
            mid = (start + end) // 2
            left_child = 2 * node + 1
            right_child = 2 * node + 2
            self.build(arr, left_child, start, mid)
            self.build(arr, right_child, mid + 1, end)
            self.tree[node] = self.merge(self.tree[left_child], self.tree[right_child])

    def merge(self, left, right):
        merged = self.Node(0)
        merged.total = left.total + right.total
        merged.best_prefix = max(left.best_prefix, left.total + right.best_prefix)
        merged.best_suffix = max(right.best_suffix, right.total + left.best_suffix)
        merged.best_sum = max(left.best_suffix + right.best_prefix, left.best_sum, right.best_sum)
        return merged

    def update(self, index, value, node=0, start=0, end=None):
        if end is None:
            end = self.n - 1

        if start == end:
            self.tree[node] = self.Node(value)
        else:
            mid = (start + end) // 2
            left_child = 2 * node + 1
            right_child = 2 * node + 2
            if index <= mid:
                self.update(index, value, left_child, start, mid)
            else:
                self.update(index, value, right_child, mid + 1, end)
            self.tree[node] = self.merge(self.tree[left_child], self.tree[right_child])

    def query(self, l, r, node=0, start=0, end=None):
        if end is None:
            end = self.n - 1

        if r < start or l > end:
            return self.Node(float('-inf'))  # Nodo nulo para combinaciones
        if l <= start and end <= r:
            return self.tree[node]

        mid = (start + end) // 2
        left_child = 2 * node + 1
        right_child = 2 * node + 2
        left_result = self.query(l, r, left_child, start, mid)
        right_result = self.query(l, r, right_child, mid + 1, end)
        return self.merge(left_result, right_result)

# Construct segment tree
seg_tree = SegmentTree(arr)

# Process operations dynamically
outputs = []
for query in queries:
    parts = query.split()
    if parts[0] == 'U':
        i, x = int(parts[1]) - 1, int(parts[2])
        seg_tree.update(i, x)
    elif parts[0] == 'Q':
        l, r = int(parts[1]) - 1, int(parts[2]) - 1
        result = seg_tree.query(l, r)
        outputs.append(str(result.best_sum))

# Print all query results
print("\n".join(outputs))
```

```

HTB{DR4G0N_FL1GHT_5TR33_3d89554699afbac5c68c83aec83515e8}

```
