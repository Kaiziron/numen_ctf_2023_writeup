# Numen CTF 2023 : Asslot

### Contract code :
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

contract Asslot {

    event EmitFlag(address);

    constructor() {
    }

    function func() private view {
        assembly {
            for { let i := 0 } lt(i, 0x4) { i := add(i, 1) } {
                mstore(0, blockhash(sub(number(), 1)))
                let success := staticcall(gas(), caller(), 0, shl(0x5, 1), 0, 0)
                if eq(success, 0) { invalid() }
                returndatacopy(0, 0, shl(0x5, 1))
                switch eq(i, mload(0))
                case 0 { invalid() }
            }
        }
    }

    function f00000000_bvvvdlt() external {
        assembly {
            let size := extcodesize(caller())
            if gt(size, shl(0x6, 1)) { invalid() }
        }
        func();
        emit EmitFlag(tx.origin);
    }

}
```

Our goal is to call `f00000000_bvvvdlt()` to emit the `EmitFlag` event

It will check the extcodesize of the caller, and require that it's not greater than 64 bytes

Then it will do a static call to the caller in a loop with 4 iterations, with the blockhash of the last block as calldata, and it will check if the return data of the static call equals to `i`

So basically, we have to write a contract directly with opcodes that it is not longer than 64 bytes and it returns 0, 1, 2, 3 in the ascending order, also it need to be able to call the asslot contract at first

One way to solve this is to use the calculate the gas left during the 4 static call, and accurately make them become 0, 1, 2, 3

But an easier way is to just bruteforce with pseudo random return data, as there are just 4 numbers :

```
CALLVALUE
PUSH1 0x00
EQ
PUSH1 0x18
JUMPI
PUSH1 0x00
DUP1
MSTORE
PUSH1 0x00
DUP1
PUSH1 0x04
DUP2
DUP1
PUSH1 0x00
CALLDATALOAD
GAS
CALL
STOP
JUMPDEST
PUSH1 0x04
PUSH1 0x01
NUMBER
SUB
BLOCKHASH
PUSH1 0x00
MSTORE
GAS
PUSH1 0x20
MSTORE
PUSH1 0x40
PUSH1 0x00
SHA3
MOD
PUSH1 0x00
MSTORE
PUSH1 0x20
PUSH1 0x00
RETURN

3460001460185760008052600080600481806000355af1005b600460014303406000525a60205260406000200660005260206000f3
```

If we send value > 0 to it and passing the asslot contract as calldata (padded with zeros), it will call `f00000000_bvvvdlt()` of the asslot contract

If it is called with value == 0, it will return a pseudo number in the range of 0 - 3 using the keccak256 hash of last block's blockhash and the gas left and mod 4

We can either bruteforce with different gasLimit or wait for another block

I did not finish this during the CTF, as someone in my team have already solved it, so I tried it after the CTF in foundry :

(Deployer in deploy_bytecode.sol will just return the bytes passed to it in the constructor, storing that as the runtime bytecode)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/asslot.sol";
import "../src/deploy_bytecode.sol";

contract asslotTest is Test {
    Asslot public asslot;
    Deployer public bytecode;

    function setUp() public {
        asslot = new Asslot();
    }

    function testSolved() public {
        bytecode = new Deployer(hex"3460001460185760008052600080600481806000355af1005b600460014303406000525a60205260406000200660005260206000f3");
        console.logBytes32(blockhash(block.number - 1));
        console.log(block.number);
        uint256 gasLimit = 1000000;
        vm.recordLogs();
        while (true) {
            (bool success,) = address(bytecode).call{value: 1 wei, gas: gasLimit}(abi.encode(address(asslot)));
            Vm.Log[] memory logs = vm.getRecordedLogs();
            if (logs.length > 0 && logs[0].topics[0] == keccak256(abi.encodePacked("EmitFlag(address)")) && logs[0].emitter == address(asslot)) {
                console.log(gasLimit);
                console.log(logs.length);
                console.logBytes32(logs[0].topics[0]);
                console.logBytes(logs[0].data);
                console.log(logs[0].emitter);
                break;
            }
            ++gasLimit;
        }
    }
}
```

```
# forge test --match-path test/asslot.t.sol -vv
[⠒] Compiling...
No files changed, compilation skipped

Running 1 test for test/asslot.t.sol:asslotTest
[PASS] testSolved() (gas: 407137595)
Logs:
  0x290decd9548b62a8d60345a988386fc84ba6bc95484008f6362f93160ef3e563
  1
  1000409
  1
  0xaa819c6c26f823380741c0a4e7d972859d613b5b9a3cdfbb98c18383106c5e95
  0x0000000000000000000000001804c8ab1f12e6bbf3894d4083f33e07309d1f38
  0x5615dEB798BB3E4dFa0139dFa1b3D433Cc23b72f

Test result: ok. 1 passed; 0 failed; finished in 17.66ms
```