# Numen CTF 2023 : HEXP

### Contract code :
```solidity
pragma solidity ^0.8.0;

contract Hexp {
    address public immutable target;
    bool flag;

    constructor() {
        bytes memory code = hex"3d602d80600a3d3981f362ffffff80600a43034016903a1681146016576033fe5b5060006000f3";
        address child;
        assembly {
            child := create(0, add(code, 0x20), mload(code))
        }
        target = child;
    }

    function f00000000_bvvvdlt() external {
        (bool succ, bytes memory ret) = target.call(hex"");
        assert(succ);
        flag = true;
    }

    function isSolved() public view returns (bool) {
        return flag;
    }
}
```

The objective is to set flag to true, `f00000000_bvvvdlt()` will call the contract deployed in the constructor with empty calldata, and if the call success, then it will set flag to true, just like the EVM puzzles

In constructor, it will create a contract with the creation code of `3d602d80600a3d3981f362ffffff80600a43034016903a1681146016576033fe5b5060006000f3`, which will return the runtime bytecode of this : 
```
PUSH3 0xffffff
DUP1
PUSH1 0x0a
NUMBER
SUB
BLOCKHASH
AND
SWAP1
GASPRICE
AND
DUP2
EQ
PUSH1 0x16
JUMPI
PUSH1 0x33
INVALID
JUMPDEST
POP
PUSH1 0x00
PUSH1 0x00
RETURN
STOP
STOP
STOP
STOP
STOP
STOP
STOP
STOP
STOP
STOP
STOP
STOP
STOP
STOP
STOP
STOP

62ffffff80600a43034016903a1681146016576033fe5b5060006000f300000000000000000000000000000000
```

So basically what it does is get the blockhash of 10 blocks before and do bitwise and with the blockhash and `0xffffff`, and get the gas price and do bitwise and of the gas price and `0xffffff`, and compare if they are the same, if yes then it will jump and finish the execution, otherwise it will revert

As doing bitwise and with `0xffffff` is basically just taking the 6 least significant hex digit, so we have to submit a transaction that the 6 least significant hex digit of the gas price is the same as the 6 least significant hex digit of the blockhash of 10 blocks before

We can just write a script to get the blockhash of 10 blocks before the block our transaction gets included, assuming our transaction will be mined in the next block, then set the gas price accordingly 

### Solve script :
```python
from web3 import Web3, HTTPProvider
from web3.middleware import geth_poa_middleware

web3 = Web3(HTTPProvider('http://8.218.239.44:8545/'))
web3.middleware_onion.inject(geth_poa_middleware, layer=0) 


from_acc = '0xC9d88f58258B264b6110D6D0d4612c3228DaeEfc'
private_key = '0xc41402539e8875ba2e4c5ef1f08aac6ba86c32218d585a068447ac5710adf414'

to_acc = '0xA9128DFAA633F3F5d16d8d5E9A73214a57de919B'

nonce = web3.eth.getTransactionCount(from_acc)
number = web3.eth.get_block_number() + 1
print("Block num to be mined: ", number)
blockhash = web3.eth.get_block(number - 10).hash.hex()
print("Blockhash of 10 blocks before : ", blockhash)
gasPrice = int(hex(int(hex(int(blockhash, 16) & 0xffffff),16) + 0x100000000 + 0x10000000),16)
print(hex(gasPrice))
gasLimit = 3000000
value = 0

tx = {
    'nonce': nonce,
    'to': to_acc,
    'value': value,
    'gas': gasLimit,
    'gasPrice': gasPrice,
    'chainId': 22574,
    'data': "0x00000000"
}

signed_tx = web3.eth.account.sign_transaction(tx, private_key)
tx_hash = web3.eth.sendRawTransaction(signed_tx.rawTransaction)
transaction_hash = web3.toHex(tx_hash)
tx_receipt = web3.eth.wait_for_transaction_receipt(transaction_hash)
print(transaction_hash)
print(tx_receipt['status'])
```

### Flag :
```
# nc 8.218.239.44 24000
Can you make the isSolved() function return true?

[1] - Create an account which will be used to deploy the challenge contract
[2] - Deploy the challenge contract using your generated account
[3] - Get your flag once you meet the requirement
[4] - Show the contract source code
[-] input your choice: 3
[-] input your token: v4.local.ezkDMKKukCaPIIiBw44moBiaXzr0SkvBK4-9Zqw0riJ310U4A0U04dOJU5pxRy8ZkCF_zoToZ9qe2tLbk6A4gUQtjzDtj6Gy-6Di_uqPRdUwlWzKPiLvlzqUlEj49oCPkccKe4n6nXAuS8uDV84izHGuKxrHNmJpVymLrTxnV47B3A.SGV4cA
[+] flag: flag{0xdd4672257e7adf56f0896c33747caf793fcd1e53}
```