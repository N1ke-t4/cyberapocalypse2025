# HTB 2025 CTF - ML Enchanted Weights

## Challenge Description
This challenge provides a PyTorch model file (`eldorian_artifact.pth`) that contains a hidden flag.

## Solution

The challenge presents us with a `.pth` file, which is the standard file extension for PyTorch model weights. However, this is more than just a standard model file.

### Initial Examination

First, I started by checking what type of file we're dealing with:

```bash
file eldorian_artifact.pth
```

Which revealed that it's actually a ZIP archive:

```
eldorian_artifact.pth: Zip archive data, at least v0.0 to extract, compression method=store
```

### Exploring the Archive Contents

Since PyTorch model files are saved in a specific format that includes multiple files packed together, I extracted the contents to analyze them:

```python
import zipfile
import io

with open("eldorian_artifact.pth", "rb") as f:
    content = f.read()

with zipfile.ZipFile(io.BytesIO(content), 'r') as z:
    z.extractall("extracted_artifact")
```

The archive contained several files:

```
eldorian_artifact/data.pkl - 259 bytes
eldorian_artifact/byteorder - 6 bytes
eldorian_artifact/data/0 - 6400 bytes
eldorian_artifact/version - 2 bytes
eldorian_artifact/.data/serialization_id - 40 bytes
```

### Analysis of Model Weights

The key insight came from analyzing the binary data in `eldorian_artifact/data/0` which contained the model weights. This file is 6400 bytes, and since a float32 value is 4 bytes, it would contain 1600 float values.

I used NumPy to read and reshape this data:

```python
import numpy as np

# Load the binary data file
with open("extracted_artifact/eldorian_artifact/data/0", "rb") as f:
    bin_data = f.read()

# Parse as float32 array
float_array = np.frombuffer(bin_data, dtype=np.float32)
print(f"Shape: {float_array.shape}")  # 1600 elements

# Reshape to a 40x40 grid to visualize
grid = float_array.reshape(40, 40)
```

### Visualizing the Hidden Pattern

When I visualized this 40×40 grid, I noticed an interesting diagonal pattern. Most values were zeros, but there were non-zero values forming a diagonal line:

```
ASCII Visualization (higher values = darker):
*                                       
 *                                      
  *                                     
   #                                    
    *                                   
     #                                  
      #                                 
       +                                
        #                               
         +                              
          #                             
           #                            
            *                           
             #                          
              *                         
               +                        
                #                       
                 #                      
                  +                     
                   #                    
                    #                   
                     *                  
                      #                 
                       #                
                        +               
                         #              
                          +             
                           #            
                            #           
                             #          
                              #         
                               #        
                                #       
                                 #      
                                  #     
                                   #    
                                    #   
                                     #  
                                      # 
                                       #
```

### Decoding the Flag

The key insight was to interpret these non-zero values as ASCII character codes. When I did that, the pattern became clear:

```
Trying to interpret as ASCII art (characters):
H                                       
 T                                      
  B                                     
   {                                    
    C                                   
     r                                  
      y                                 
       5                                
        t                               
         4                              
          l                             
           _                            
            R                           
             u                          
              N                         
               3                        
                s                       
                 _                      
                  0                     
                   f                    
                    _                   
                     E                  
                      l                 
                       d                
                        0               
                         r              
                          1             
                           a            
                            }           
                             _          
                              _         
                               _        
                                _       
                                 _      
                                  _     
                                   _    
                                    _   
                                     _  
                                      _ 
                                       _
```

### Extracting the Flag

Collecting all the non-zero values and interpreting them as ASCII characters revealed the flag:

```python
# Extract all non-zero values as ASCII and check for patterns
non_zero_vals = [val for val in float_array if val != 0]
ascii_chars = []
for val in non_zero_vals:
    ascii_val = int(val)
    if 32 <= ascii_val <= 126:  # Printable ASCII range
        ascii_chars.append(chr(ascii_val))

text = ''.join(ascii_chars)
print(f"\nNon-zero values as ASCII: {text}")
```

Which gave us:

```
Non-zero values as ASCII: HTB{Cry5t4l_RuN3s_0f_Eld0r1a}___________
```

The flag is: `HTB{Cry5t4l_RuN3s_0f_Eld0r1a}`

## Key Takeaways

1. Machine learning model files can hide data within their weights
2. The PyTorch `.pth` files are actually ZIP archives
3. Model weights can encode messages when interpreted as ASCII values
4. Visualizing the data in different ways can reveal hidden patterns

This challenge demonstrates a creative way to hide data within what appears to be a legitimate machine learning model file, using the model weights themselves as a steganographic medium.
