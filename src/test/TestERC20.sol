pragma solidity ^0.8.0;

import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";

contract TestERC20 is ERC20 {
    constructor(address recipient, uint256 amount) ERC20("TST", "TestToken") {
        _mint(recipient, amount);
    }
}