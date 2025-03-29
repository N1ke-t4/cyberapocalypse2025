# ML Crystal Corruption - HTB Machine Learning CTF Write-Up

## Challenge Description
This challenge presented a PyTorch model file (`resnet18.pth`) that appears to be a standard ResNet18 model, but contains a hidden flag embedded within the model weights.

## Investigation Process

### Initial Analysis
First, I examined the provided file to understand what we're working with:

```bash
ls -la resnet18.pth
```

The file was about 46MB, which is consistent with a typical ResNet18 model.

### Attempted Loading
When attempting to load the model directly with PyTorch, I encountered a suspicious payload execution:

```python
import torch
model = torch.load('resnet18.pth', map_location=torch.device('cpu'), weights_only=False)
```

This displayed:
```
Connecting to 127.0.0.1
Delivering payload to 127.0.0.1
Executing payload on 127.0.0.1
You have been pwned!
```

### File Structure Analysis
Looking closer at the file's structure revealed it was actually a ZIP archive containing model data:

```bash
# Checking the file header
hexdump -C resnet18.pth | head -100
```

The hexdump revealed a PK header (ZIP file signature) and Python pickle data including imports for `sys` and `torch`, along with a suspicious function called `stego_decode`.

### Extracting the Payload
After analyzing the file structure, I wrote a Python script to safely extract the model's data without executing the malicious code:

```python
import zipfile
import struct
import numpy as np

def stego_decode(tensor_bytes, n=3):
    """Safe implementation of stego_decode without executing code"""
    try:
        tensor = np.frombuffer(tensor_bytes, dtype=np.uint8)
        bits = np.unpackbits(tensor)
        
        # Extract least significant bits (steganography technique)
        itemsize = 4  # Assuming float32
        extracted_bits = []
        for i in range(8-n, 8):
            extracted_bits.append(bits[i::itemsize * 8])
        
        stacked = np.vstack(tuple(extracted_bits)).ravel(order='F')
        payload = np.packbits(stacked).tobytes()
        
        # Try to extract the structured data
        (size, checksum) = struct.unpack("i 64s", payload[:68])
        message = payload[68:68+size]
        return message
    except Exception as e:
        print(f"Error decoding: {e}")
        return None

# Extract and decode all tensor data files
with zipfile.ZipFile('resnet18.pth', 'r') as zip_ref:
    for file_name in zip_ref.namelist():
        if file_name.startswith('resnet18/data/'):
            try:
                tensor_bytes = zip_ref.read(file_name)
                result = stego_decode(tensor_bytes)
                
                if result:
                    try:
                        decoded = result.decode('utf-8')
                        if 'HTB' in decoded:
                            print(f"Found in {file_name}: {decoded}")
                    except:
                        pass
            except Exception as e:
                pass
```

## The Hidden Malicious Code

When examining the first data file (`resnet18/data/0`), I discovered this malicious code:

```python
import os

def exploit():
    connection = f"Connecting to 127.0.0.1"
    payload = f"Delivering payload to 127.0.0.1"
    result = f"Executing payload on 127.0.0.1"

    print(connection)
    print(payload)
    print(result)

    print("You have been pwned!")

hidden_flag = "HTB{n3v3r_tru5t_p1ckl3_m0d3ls}"

exploit()
```

## The Flag

The flag was hidden in the model weights:

```
HTB{n3v3r_tru5t_p1ckl3_m0d3ls}
```

## Key Takeaways

1. **Pickle Insecurity**: This challenge demonstrates why you should never load untrusted pickle files or model weights without proper security measures.

2. **Steganography in ML Models**: The challenge used a clever technique to hide data in the least significant bits of model tensor values.

3. **Safe Loading**: PyTorch now defaults to `weights_only=True` for loading models to prevent this type of attack, but older versions might be vulnerable.

4. **Code Execution Risk**: ML models loaded with pickle can execute arbitrary code as shown in this example. Always load models from trusted sources or in a sandboxed environment.

By analyzing the file structure and safely extracting the tensor data without executing the malicious code, I was able to recover the hidden flag and learn about an interesting machine learning security vulnerability.
