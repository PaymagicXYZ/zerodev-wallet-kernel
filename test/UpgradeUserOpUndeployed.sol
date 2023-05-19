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
import {KernelV2} from "src/test/KernelV2.sol";

using ECDSA for bytes32;

contract UpgradeUserOpTest is Test {
    KernelFactory factory;
    Kernel kernel;
    KernelV2 kernelV2;
    IEntryPoint entryPoint;
    MultiSend multiSend;
    TestERC20 token;
    address user1;
    address expectedAddress;
    uint256 user1PrivKey;
    address payable bundler;

    function signUserOp(
        UserOperation memory op,
        address addr,
        uint256 key
    ) public view returns (bytes memory signature) {
        bytes32 hash = entryPoint.getUserOpHash(op);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(
            key,
            hash.toEthSignedMessageHash()
        );
        require(addr == ECDSA.recover(hash.toEthSignedMessageHash(), v, r, s));
        signature = abi.encodePacked(r, s, v);
        require(
            addr == ECDSA.recover(hash.toEthSignedMessageHash(), signature)
        );
    }

    function setUp() public {
        entryPoint = new EntryPoint();
        factory = new KernelFactory(entryPoint);
        kernelV2 = new KernelV2(entryPoint);

        (user1, user1PrivKey) = makeAddrAndKey("user1");
        uint256 index = 0;

        bundler = payable(makeAddr("bundler"));

        expectedAddress = factory.getAccountAddress(user1, index);
        token = new TestERC20(address(expectedAddress), 10 ether);
        multiSend = new MultiSend();
        assertEq(token.balanceOf(address(expectedAddress)), 10 ether);

        entryPoint.depositTo{value: 1000000000000000000}(user1);
    }

    function testExecuteUserOp() public {
        // kernel = Kernel(payable(address((proxy))));
        // assertEq(kernel.getOwner(), user1);
        // assertEq(address(kernel.entryPoint()), address(entryPoint));
        bytes memory callData = abi.encodeWithSelector(
            kernel.upgradeTo.selector,
            address(kernelV2)
        );

        bytes memory initCode = abi.encodeCall(
            KernelFactory.createAccount,
            (user1, 0)
        );

        bytes memory initCodeFull = abi.encodePacked(
            address(factory),
            initCode
        );

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = UserOperation({
            sender: address(expectedAddress),
            nonce: 0,
            initCode: initCodeFull,
            callData: abi.encodeCall(
                Kernel.executeAndRevert,
                (address(expectedAddress), 0, callData, Operation.Call)
            ),
            callGasLimit: 2000000,
            verificationGasLimit: 5000000,
            preVerificationGas: 1000000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 1,
            paymasterAndData: hex"",
            signature: hex""
        });
        ops[0].signature = signUserOp(ops[0], user1, user1PrivKey);

        entryPoint.handleOps(ops, bundler);

        KernelV2 kernelV1Upgraded = KernelV2(
            payable(address((expectedAddress)))
        );

        assertEq(kernelV1Upgraded.getOwner(), user1);

        assertEq(kernelV1Upgraded.hello(), "hello");
    }
}
