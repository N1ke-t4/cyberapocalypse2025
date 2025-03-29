**Stealth Invasion Write-Up**
# HTB 2025 Forensics Challenge Writeup: Malicious Chrome Extension

## Challenge Overview
This challenge provided a memory dump file (memdump.elf) and required analysis of a malicious Chrome extension to find several pieces of information.

## Tools Used
- Volatility 3
- Basic command line utilities (strings, grep)
- Linux bash environment

## Step 1: Identifying the original Chrome process
The first task was to find the PID of the original Chrome process. Using Volatility 3, we examined the running processes:

```bash
vol -f memdump.elf windows.pslist
```

After analyzing the output, we identified PID 4080 as the original Chrome process.

## Step 2: Finding a suspicious folder on Desktop
The second question asked about a folder on the victim's Desktop. By examining the memory dump, we found a folder called "malext":

```bash
strings memdump.elf | grep -i "Desktop.*malext"
```

The folder path was `C:\Users\selene\Desktop\malext`.

## Step 3: Identifying the Extension ID
For the third task, we needed to identify the malicious extension's ID. Using string searches, we found:

```bash
strings memdump.elf | grep -C 10 "Malext"
```

This revealed the extension ID: `nnjofihdjilebhiiemfmdlpbdkbjcpae`.

## Step 4: Finding the log filename
The most challenging part was identifying the log file where the extension stores stolen data. After multiple searches through the memory dump:

```bash
strings memdump.elf | grep -i "000003.log"
```

We found that the extension was using `000003.log` as its log file. This is a standard Chrome log file format used within extension storage.

Evidence found in the memory dump:
```
2025/03/13-10:01:11.295 1900 Reusing old log C:\Users\selene\AppData\Local\Google\Chrome\User Data\Default\Extension Scripts/000003.log
```

## Step 5: Identifying the URL the user navigated to
By searching through browser history data in the memory dump, we found:

```bash
strings memdump.elf | grep -i "drive.google.com"
```

The URL the user navigated to was `drive.google.com`.

## Step 6: Finding stored credentials
The final task was to find a password stored in the memory. Through string analysis:

```bash
strings memdump.elf | grep -i "password" | grep -i "selene"
```

We found the password "clip-mummify-proofs" associated with the email address selene@rangers.eldoria.com.

## Summary of Findings
1. Chrome PID: 4080
2. Folder on Desktop: malext
3. Extension ID: nnjofihdjilebhiiemfmdlpbdkbjcpae
4. Log filename: 000003.log
5. URL navigated to: drive.google.com
6. Password: clip-mummify-proofs

## Lessons Learned
- Memory forensics provides valuable information about malicious activities
- Chrome extensions can be used as vectors for credential theft
- Understanding browser storage mechanisms is crucial for forensic analysis
- Sometimes the most valuable data is in standard log files rather than custom-named files

## Conclusion
This challenge demonstrated practical memory forensics techniques for investigating browser-based malware. The malicious extension was using Chrome's built-in storage and logging mechanisms to capture user credentials, highlighting how attackers can abuse legitimate browser functionality.
