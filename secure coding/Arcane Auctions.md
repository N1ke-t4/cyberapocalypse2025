# Arcane Auctions Secure Coding

**Write-UP:**

## 1. Overview

We exploited a multi-stage vulnerability in the Node.js application deployed via Docker. The chain leveraged an insecure filtering endpoint, weak authentication, and an exposed SMB share that allowed us to modify source code on the fly. Ultimately, this allowed us to inject a malicious route to read the contents of `/flag.txt`—which is owned by root and located at the container’s root directory.

## 2. Vulnerability Chain

### a. Insecure Filter Endpoint

- **Endpoint:** POST `/api/filter`
- **Vulnerability:**  
  The endpoint accepts a Prisma-style filter object without sanitization. This allowed us to craft a payload to leak sensitive seller data, including plaintext credentials.
- **Impact:**  
  By abusing this endpoint, we were able to extract valid user credentials from the database.

### b. Weak Authentication

- **Login Endpoint:** POST `/login`
- **Credentials:**  
  Using the leaked data, we obtained valid credentials (e.g., `tarnished@arcane.htb` with password `07e172faa63c6178`).
- **Impact:**  
  With these credentials, we successfully authenticated and established a session necessary for further exploitation.

### c. Exposed SMB Share

- **Port:** 445
- **Vulnerability:**  
  The SMB share (as mentioned in `note.md`) provides write access to the application’s source code.
- **Impact:**  
  By mounting the SMB share, we gained direct access to the application files (e.g., `routes.js`), enabling us to modify the server-side code.

### d. Code Injection via Routes Modification

- **Injection Target:** `routes.js`
- **Malicious Payload:**  
  We appended a new endpoint `/flag` that reads the contents of `/flag.txt` using a dynamic import for the `fs` module. This change was necessary because the application uses ES modules, where `require` is not defined.

  ```javascript
  router.get('/flag', async (req, res) => {
    try {
      const fs = await import('fs');
      fs.readFile('/flag.txt', 'utf8', (err, data) => {
        if (err) {
          console.error('Error reading flag.txt:', err);
          return res.status(500).send('Error reading flag.');
        }
        res.send(data);
      });
    } catch (error) {
      console.error('Error importing fs:', error);
      res.status(500).send('Error reading flag.');
    }
  });
  ```

- **Impact:**  
  Once injected and saved, nodemon automatically detected the change, restarted the Node process, and loaded the new endpoint. This allowed us to access the flag by visiting the `/flag` route.

### e. Automatic Reloading with Nodemon

- **Nodemon Role:**  
  The application runs under nodemon (as configured in the supervisor). Nodemon monitors the project files for changes and automatically restarts the Node.js application when a change is detected.
- **Impact:**  
  Once we modified `routes.js`, nodemon reloaded the server automatically without requiring a manual restart. This behavior allowed our injected `/flag` endpoint to become active almost immediately, enabling us to retrieve the flag.

## 3. Exploitation Steps

- **Credential Extraction:**  
  We sent a crafted JSON payload to the `/api/filter` endpoint to leak seller data, which revealed valid credentials.

- **Authentication:**  
  Using the leaked credentials (`tarnished@arcane.htb` / `07e172faa63c6178`), we logged into the application via the `/login` endpoint.

- **SMB Share Mounting:**  
  Following instructions from `note.md`, we mounted the SMB share (e.g., using `mount -t cifs //<IP>/app ~/mnt/ -o username=guest,port=<PORT>`) to gain write access to the application’s source code.

- **Code Injection:**  
  We modified `routes.js` on the mounted share by appending our malicious `/flag` endpoint. Because the server uses nodemon, the change was automatically detected, and the Node.js process reloaded with our new code.

- **Flag Retrieval:**  
  Finally, we accessed `http://<target_address>/flag` (e.g., `http://83.136.254.193/flag`), which triggered our injected endpoint to read and return the contents of `/flag.txt`.

## 4. Conclusion

This exploit chain demonstrates the importance of secure API design and proper access controls:

- **Sanitization:** Unsanitized filter inputs allowed arbitrary data selection.
- **Authentication:** Storing passwords in plaintext enabled easy authentication.
- **Access Control:** An exposed SMB share gave attackers write access to critical application files.
- **Code Injection:** Combining these flaws allowed us to inject code that reads sensitive files.

Furthermore, the use of nodemon for automatic reloading was critical in our attack, as it ensured our modifications were applied immediately without manual intervention. This chain allowed us to ultimately extract the flag from the container's root directory.

**FLAG:** `HTB{l00k_0ut_f0r_0rm_l34k_bug_cut13_666aafc58da9e3ebfd64e44419efa218}`
