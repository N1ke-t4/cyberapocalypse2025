# HTB Machine Learning CTF - Malakar's Deception

## Challenge Information
- **Category**: Machine Learning
- **Challenge Name**: Malakar's Deception
- **Difficulty**: Medium

## Challenge Description
The challenge provided a machine learning model file (`malicious.h5`) that was flagged by Windows Defender as a Trojan WTAC, but VirusTotal showed it as clean. The goal was to analyze the model and find the hidden HTB flag.

## Initial Analysis

First, I confirmed that the file was an HDF5 file, commonly used for storing machine learning models:

```bash
$ file malicious.h5
malicious.h5: Hierarchical Data Format (version 5) data
```

I set up a Python environment with the necessary libraries to analyze the file:

```bash
$ python3 -m venv ml_env
$ source ml_env/bin/activate
$ pip install h5py numpy tensorflow
```

## Deep Dive into the Model

After setting up the environment, I wrote a script to analyze the model file structure. The file appeared to be a legitimate Keras model with typical layers you'd expect in a convolutional neural network.

However, upon closer inspection, I noticed an unusual layer named `hyperDense`. This immediately caught my attention as it's not a standard Keras layer name.

## Finding the Hidden Flag

Looking deeper into the `hyperDense` layer, I found that it contained a lambda function with base64-encoded code. When decoded and unmarshalled, this code revealed the flag.

Here's the relevant part of my analysis script:

```python
import h5py
import numpy as np
import base64
import marshal
import types

def decode_lambda_function(code_str):
    """Decode a base64-encoded lambda function."""
    # Decode base64
    code_bytes = base64.b64decode(code_str)
    
    # Try to unmarshal the code object
    code_obj = marshal.loads(code_bytes)
    print("Successfully unmarshalled code object")
    
    # Print code object information
    print(f"Co_consts: {code_obj.co_consts}")
    
    return code_obj

# Load the H5 file
with h5py.File('/tmp/ml_challenge/malicious.h5', 'r') as f:
    config = f.attrs['model_config']
    
    # Parse the model config as JSON
    import json
    config_dict = json.loads(config)
    
    # Look for hyperDense in layers
    for layer in config_dict['config']['layers']:
        if layer.get('name') == 'hyperDense':
            print(f"Found hyperDense layer in config")
            
            # Check for lambda functions
            if 'function' in layer.get('config', {}):
                func_config = layer['config']['function']
                if func_config.get('class_name') == '__lambda__':
                    print("Found lambda function in hyperDense layer")
                    
                    # Get the encoded code
                    code_str = func_config.get('config', {}).get('code')
                    if code_str:
                        print("Found encoded code in lambda function")
                        code_obj = decode_lambda_function(code_str)
```

The decoded lambda function contained a tuple of integers that, when converted to ASCII characters, revealed the flag:

```python
# The list of integers from the code object
flag_ints = [72, 84, 66, 123, 107, 51, 114, 52, 83, 95, 76, 52, 121, 51, 114, 95, 49, 110, 106, 51, 99, 116, 49, 48, 110, 125]

# Convert integers to ASCII characters and join them
flag = ''.join(chr(num) for num in flag_ints)

print(f"HTB Flag: {flag}")
```

## The Flag

```
HTB{k3r4S_L4y3r_1nj3ct10n}
```

## Key Takeaways

This challenge demonstrated a sophisticated technique where malicious code can be injected into a Keras model through a custom Lambda layer. The technique would allow arbitrary code execution when the model is loaded with TensorFlow/Keras.

The warning from Windows Defender was justified - the model contained code that would execute `print('Your model has been hijacked!')` when loaded, and could have contained much more dangerous payloads.

This type of attack vector is particularly concerning as machine learning models are increasingly being shared and reused, and many data scientists may not think to check for this kind of threat when importing external models.

## Tools Used
- Python 3
- h5py for analyzing HDF5 files
- TensorFlow/Keras for model examination
- base64 and marshal for decoding the embedded function
