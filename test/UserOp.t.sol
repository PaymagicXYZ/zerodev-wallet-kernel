// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";

import "account-abstraction/core/EntryPoint.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";

import {KernelFactory} from "src/KernelFactory.sol";
import {Kernel, KernelStorage, Operation} from "src/Kernel.sol";
import {EIP1967Proxy} from "src/factory/EIP1967Proxy.sol";
import {TestERC20} from "src/test/TestERC20.sol";
import {MultiSend} from "src/test/MultiSend.sol";

using ECDSA for bytes32;


contract UserOpTest is Test {
    KernelFactory factory;
    Kernel kernel;
    IEntryPoint entryPoint;
    MultiSend multiSend;
    TestERC20 token;
    address user1;
    uint256 user1PrivKey;
    address payable bundler;





    function signUserOp(UserOperation memory op, address addr, uint256 key)
        public
        view
        returns (bytes memory signature)
    {
        bytes32 hash = entryPoint.getUserOpHash(op);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, hash.toEthSignedMessageHash());
        require(addr == ECDSA.recover(hash.toEthSignedMessageHash(), v, r, s));
        signature = abi.encodePacked(r, s, v);
        require(addr == ECDSA.recover(hash.toEthSignedMessageHash(), signature));
    }

    function setUp() public {
        entryPoint = new EntryPoint();
        factory = new KernelFactory(entryPoint);
        (user1, user1PrivKey) = makeAddrAndKey("user1");
                uint256 index = 0;

        bundler = payable(makeAddr("bundler"));

        EIP1967Proxy proxy = factory.createAccount(user1, index);
        kernel = Kernel(payable(address((proxy))));
        address expectedAddress = factory.getAccountAddress(user1, index);
        token = new TestERC20(address(proxy), 10 ether);
        multiSend = new MultiSend();
        assertEq(token.balanceOf(address(proxy)), 10 ether);

        assertEq(address(proxy), expectedAddress);

        entryPoint.depositTo{value: 1000000000000000000}(user1);
    }

    function testExecuteDirect() public {
        // kernel = Kernel(payable(address((proxy))));
        assertEq(kernel.getOwner(), user1);
        assertEq(address(kernel.entryPoint()), address(entryPoint));

        // UserOperation[] memory ops = new UserOperation[](1);

        bytes memory callData = abi.encodeWithSelector(token.transfer.selector, address(0x123), 10 ether);
        // callData = abi.encodeWithSelector(kernel.executeAndRevert(to, value, data, operation);, arg);

        vm.prank(user1);
        kernel.executeAndRevert(address(token), 0, callData, Operation.Call);

        assertEq(token.balanceOf(address(0x123)), 10 ether);
       
    }

    function testExecuteUserOp() public {
        // kernel = Kernel(payable(address((proxy))));
        assertEq(kernel.getOwner(), user1);
        assertEq(address(kernel.entryPoint()), address(entryPoint));

        // UserOperation[] memory ops = new UserOperation[](1);

          bytes memory callData = abi.encodeWithSelector(token.transfer.selector, address(0x123), 10 ether);
        
        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = UserOperation({
            sender: address(kernel),
            nonce: 0,
            initCode:  hex"",
            callData: abi.encodeCall(
                Kernel.executeAndRevert, (address(token), 0, callData, Operation.Call)
                ),
            callGasLimit: 2000000,
            verificationGasLimit: 500000,
            preVerificationGas: 500000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 1,
            paymasterAndData: hex"",
            signature: hex""
        });



        ops[0].signature = signUserOp(ops[0], user1, user1PrivKey);
        entryPoint.handleOps(ops, bundler);

        assertEq(token.balanceOf(address(0x123)), 10 ether);
    }

    function testExecuteUserOpMultisend() public {

            bytes memory encodedTransfer1 = abi.encodeWithSelector(token.transfer.selector, address(0x123), 5 ether);
    bytes memory encodedTransfer2 = abi.encodeWithSelector(token.transfer.selector, address(0x234), 5 ether);


    bytes memory tx1 = abi.encodePacked(
        uint8(0), // Operation.Call
        address(token), // to
        uint256(0), // value
        uint256(encodedTransfer1.length), // data length
        encodedTransfer1 // data
    );
    bytes memory tx2 = abi.encodePacked(
        uint8(0), // Operation.Call
        address(token), // to
        uint256(0), // value
        uint256(encodedTransfer2.length), // data length
        encodedTransfer2 // data
    );


        UserOperation[] memory ops = new UserOperation[](1);

        ops[0] = UserOperation({
            sender: address(kernel),
            nonce: 0,
            initCode:  hex"",
            callData: abi.encodeCall(
                Kernel.executeAndRevert, (
                    address(multiSend), // The address of the MultiSend contract
                    0,
                       abi.encodeWithSelector(MultiSend.multiSend.selector, abi.encodePacked(tx1, tx2)),
                    Operation.DelegateCall
                )
            ),
            callGasLimit: 60000000,
            verificationGasLimit: 9000000,
            preVerificationGas: 9000000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 1,
            paymasterAndData: hex"",
            signature: hex""
        });


        ops[0].signature = signUserOp(ops[0], user1, user1PrivKey);
        entryPoint.handleOps(ops, bundler);

        assertEq(token.balanceOf(address(0x123)), 5 ether);
        assertEq(token.balanceOf(address(0x234)), 5 ether);

    }
}
