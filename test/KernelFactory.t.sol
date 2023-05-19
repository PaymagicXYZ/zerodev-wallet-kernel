// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

import "account-abstraction/core/EntryPoint.sol";

import {KernelFactory} from "src/KernelFactory.sol";
import {Kernel, KernelStorage} from "src/Kernel.sol";
import {EIP1967Proxy} from "src/factory/EIP1967Proxy.sol";

contract KernelFactoryTest is Test {
    KernelFactory factory;
    IEntryPoint entryPoint;

    function setUp() public {
        entryPoint = new EntryPoint();
        factory = new KernelFactory(entryPoint);
    }

    function testCreateAccount() public {
        address owner = address(0x123);
        uint256 index = 0;

        EIP1967Proxy proxy = factory.createAccount(owner, index);
        address expectedAddress = factory.getAccountAddress(owner, index);

        assertEq(address(proxy), expectedAddress);

        Kernel kernel = Kernel(payable(address((proxy))));
        assertEq(kernel.getOwner(), owner);
        assertEq(address(kernel.entryPoint()), address(entryPoint));
    }

}