# ClockWork Guardian

Description challenge:

```
The Clockwork Sentinels defending Eldoria's Skywatch Spire have gone rogue! You must navigate through the spire, avoiding hostile sentinels and finding the safest path to the exit.

Write an algorithm to find the shortest safe path from the start position (0,0) to the exit ('E'), avoiding the sentinels (1).

Example:

Example Grid and Output

[
    [0, 0, 1, 0, 0, 1],
    [0, 0, 0, 0, 0, 0],
    [0, 0, 0, 0, 0, 0],
    [0, 0, 1, 1, 0, 'E']
]
Output: 8

Step-by-Step Visualization:

Step 0 (Start):
Row 0: S   0   X   0   0   X
Row 1: 0   0   0   0   0   0
Row 2: 0   0   0   0   0   0
Row 3: 0   0   X   X   0   E
    
Step 1:
Row 0: S   1   X   0   0   X
Row 1: 0   0   0   0   0   0
Row 2: 0   0   0   0   0   0
Row 3: 0   0   X   X   0   E
    
Step 2:
Row 0: S   1   X   0   0   X
Row 1: 0   2   0   0   0   0
Row 2: 0   0   0   0   0   0
Row 3: 0   0   X   X   0   E
    
Step 3:
Row 0: S   1   X   0   0   X
Row 1: 0   2   3   0   0   0
Row 2: 0   0   0   0   0   0
Row 3: 0   0   X   X   0   E
    
Step 4:
Row 0: S   1   X   0   0   X
Row 1: 0   2   3   4   0   0
Row 2: 0   0   0   0   0   0
Row 3: 0   0   X   X   0   E
    
Step 5:
Row 0: S   1   X   0   0   X
Row 1: 0   2   3   4   5   0
Row 2: 0   0   0   0   0   0
Row 3: 0   0   X   X   0   E
    
Step 6:
Row 0: S   1   X   0   0   X
Row 1: 0   2   3   4   5   6
Row 2: 0   0   0   0   0   0
Row 3: 0   0   X   X   0   E
                          
Step 7:
Row 0: S   1   X   0   0   X
Row 1: 0   2   3   4   5   6
Row 2: 0   0   0   0   0   7
Row 3: 0   0   X   X   0   E
                          
Step 8 (Exit reached):
Row 0: S   1   X   0   0   X
Row 1: 0   2   3   4   5   6
Row 2: 0   0   0   0   0   7
Row 3: 0   0   X   X   0   E
                          

Path Length: 8
```


Script:

```python
from collections import deque
import ast

def shortest_safe_path(grid):
    rows, cols = len(grid), len(grid[0])
    directions = [(0,1), (1,0), (0,-1), (-1,0)]  # Right, Down, Left, Up

    # Find the exit position
    exit_pos = None
    for r in range(rows):
        for c in range(cols):
            if grid[r][c] == 'E':
                exit_pos = (r, c)
                grid[r][c] = 0  # Treat 'E' as a walkable path

    if not exit_pos:
        return -1  # No exit found

    # BFS Initialization
    queue = deque([(0, 0, 0)])  # (row, col, steps)
    visited = set()
    visited.add((0, 0))

    while queue:
        r, c, steps = queue.popleft()

        # If we reach the exit, return the shortest path length
        if (r, c) == exit_pos:
            return steps

        # Explore neighbors
        for dr, dc in directions:
            nr, nc = r + dr, c + dc

            if 0 <= nr < rows and 0 <= nc < cols and (nr, nc) not in visited:
                if grid[nr][nc] == 0:  # Only move to open paths
                    queue.append((nr, nc, steps + 1))
                    visited.add((nr, nc))

    return -1  # No path found

# Read input dynamically (input the grid as a list of lists)
grid_input = input("Enter the grid (as a list of lists): ")

# Convert the input string into a list of lists
grid = ast.literal_eval(grid_input)

# Run the function and print the shortest path
print(shortest_safe_path(grid))
```



```
HTB{CL0CKW0RK_GU4RD14N_OF_SKYW4TCH_0121471ccf16e7194b449b2a53ec7aa4}
```
