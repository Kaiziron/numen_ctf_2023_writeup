# Numen CTF 2023 : Wallet

### Contract code :
```solidity
pragma solidity ^0.8.13;

contract Deployer {
    constructor(bytes memory code) { assembly { return (add(code, 0x20), mload(code)) } }
}
contract SmartCounter{
    address public owner;
    address public target;
    bool flag=false;
    constructor(address owner_){
        owner=owner_;
    }
    function create(bytes memory code) public{
        require(code.length<=24);
        target=address(new Deployer(code));
    }

    function A_delegateccall(bytes memory data) public{
        (bool success,bytes memory returnData)=target.delegatecall(data);
        require(owner==msg.sender);
        flag=true;
    }
    function isSolved() public view returns(bool){
        return flag;
    }
}
```

The goal is to set `flag` to true, this is a fairly easy challenge, we can just set it to true with `A_delegateccall()`

It will perform a delegatecall to the target deployed with `create()`, and if we are the owner, it will set flag to true

The only requirement is that create has a code size limit to 24 bytes, but it's not a problem as long as we write our contract directly with opcodes

When we are calling `A_delegateccall()` and it is calling the target contract, our address will be `tx.origin`, and owner is in storage slot 0, so just store `tx.origin` to slot 0

```
ORIGIN
PUSH1 0x00
SSTORE

32600055
```

Call `create()` with the bytecode of `32600055`, then just call `A_delegateccall()` with empty bytes, then the challenge is solved