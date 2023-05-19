// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

import "account-abstraction/core/EntryPoint.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

import {KernelFactoryS} from "src/KernelFactoryS.sol";
import {KernelS, KernelStorage, Operation} from "src/KernelS.sol";
import {EIP1967Proxy} from "src/factory/EIP1967Proxy.sol";
import {TestERC20} from "src/test/TestERC20.sol";
import {MultiSend} from "src/test/MultiSend.sol";

using ECDSA for bytes32;

contract SigningTest is Test {
    KernelFactoryS factory;
    KernelS kernel;
    KernelS kernel2;
    IEntryPoint entryPoint;
    MultiSend multiSend;
    TestERC20 token;
    address user1;
    uint256 user1PrivKey;
    address payable bundler;

    function setUp() public {
        entryPoint = new EntryPoint();
        factory = new KernelFactoryS(entryPoint);
        uint256 index = 0;
        uint256 index2 = 1;

        EIP1967Proxy proxy = factory.createAccount(user1, index);
        EIP1967Proxy proxy2 = factory.createAccount(user1, index2);
        kernel = KernelS(payable(address((proxy))));
        kernel2 = KernelS(payable(address((proxy2))));
        console.log(address(kernel));
        console.log(address(kernel2));
    }

    function testHello() public {
        console.log(kernel.hello());
        console.log(kernel2.hello());
    }
}
