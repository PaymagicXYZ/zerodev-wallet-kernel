// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "src/factory/KernelFactory.sol";
import "src/factory/MultiKernelFactory.sol";
import "src/factory/ECDSAKernelFactory.sol";
import "src/factory/MultiECDSAKernelFactory.sol";
import "src/Kernel.sol";
import "src/validator/MultiECDSAValidator.sol";
import "src/factory/EIP1967Proxy.sol";
// test artifacts
import "src/test/TestValidator.sol";
// test utils
import "forge-std/Test.sol";
import {TestERC721} from "src/test/TestERC721.sol";
import {ERC4337Utils} from "./ERC4337Utils.sol";

using ERC4337Utils for EntryPoint;

contract DeployTest is Test {
    Kernel kernel;
    MultiKernelFactory multiKernelFactory;
    MultiECDSAKernelFactory multiECDSAKernelFactory;
    MultiECDSAValidator multiECDSAValidator;
    EntryPoint entryPoint;
    address expectedAddress;
    address owner;
    uint256 ownerKey;
    address ownerTwo;
    uint256 ownerTwoKey;

    // address[] owners;
    // address payable beneficiary;

    address payable bundler;

    TestERC721 token;

    function setUp() public {
        (owner, ownerKey) = makeAddrAndKey("owner");
        (ownerTwo, ownerTwoKey) = makeAddrAndKey("ownerTwo");

        bundler = payable(address(makeAddr("beneficiary")));

        entryPoint = new EntryPoint();

        mKernelFactory = new MultiKernelFactory(entryPoint);

        vm.prank(owner);
        multiECDSAValidator = new MultiECDSAValidator();

        assertEq(mECDSAValidator.isOwner(owner), true);

        multiECDSAKernelFactory = new MultiECDSAKernelFactory(
            multiKernelFactory,
            multiECDSAValidator,
            entryPoint
        );

        // owners[1] = ownerTwo;

        uint256 index = 99999999999999999;

        expectedAddress = multiECDSAKernelFactory.getAccountAddress(
            owner,
            index
        );

        token = new TestERC721();
        token.mint(address(expectedAddress), 1);
        assertEq(token.balanceOf(address(expectedAddress)), 1);

        // kernel = Kernel(
        //     payable(address(multiECDSAKernelFactory.createAccount(owners, 0)))
        // );
        // vm.deal(address(kernel), 1e30);
        // beneficiary = payable(address(makeAddr("beneficiary")));
    }

    function test_init_op() external {
        bytes memory initCode = abi.encodeCall(
            MultiECDSAKernelFactory.createAccount,
            (owner, 99999999999999999)
        );

        bytes memory initCodeFull = abi.encodePacked(
            address(multiECDSAKernelFactory),
            initCode
        );

        bytes memory callData = abi.encodeWithSelector(
            token.transferFrom.selector,
            address(expectedAddress),
            owner,
            1
        );

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = UserOperation({
            sender: address(expectedAddress),
            nonce: 0,
            initCode: initCodeFull,
            callData: abi.encodeCall(
                Kernel.execute,
                (address(token), 0, callData, Operation.Call)
            ),
            callGasLimit: 2000000,
            verificationGasLimit: 5000000,
            preVerificationGas: 1000000,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 1,
            paymasterAndData: hex"",
            signature: hex""
        });
        ops[0].signature = abi.encodePacked(
            bytes4(0x00000000),
            entryPoint.signUserOpHash(vm, ownerKey, ops[0])
        );
        ops[0].signature = entryPoint.signUserOpHash(vm, ownerKey, ops[0]);

        // console.logBytes(ops[0].signature);

        entryPoint.handleOps(ops, bundler);
        // assertEq(token.balanceOf(address(owner)), 1);

        //     vm.expectRevert();
        //     kernel.initialize(multiECDSAValidator, abi.encodePacked(owners));
    }

    // function test_initialize() public {
    //     Kernel newKernel = Kernel(
    //         payable(
    //             address(
    //                 new EIP1967Proxy(
    //                     address(multiKernelFactory.kernelTemplate()),
    //                     abi.encodeWithSelector(
    //                         KernelStorage.initialize.selector,
    //                         multiECDSAValidator,
    //                         abi.encode(owners)
    //                     )
    //                 )
    //             )
    //         )
    //     );
    //     for (uint i = 0; i < owners.length; i++) {
    //         multiECDSAValidator.isOwner(address(newKernel), owners[i]);
    //     }
    // }

    // function test_validate_signature() external {
    //     bytes32 hash = keccak256(abi.encodePacked("hello world"));
    //     (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(ownerKey, hash);
    //     assertEq(
    //         kernel.isValidSignature(hash, abi.encodePacked(r1, s1, v1)),
    //         Kernel.isValidSignature.selector
    //     );
    //     (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(ownerTwoKey, hash);
    //     assertEq(
    //         kernel.isValidSignature(hash, abi.encodePacked(r2, s2, v2)),
    //         Kernel.isValidSignature.selector
    //     );
    // }

    // function test_set_default_validator() external {
    //     TestValidator newValidator = new TestValidator();
    //     bytes memory empty;
    //     UserOperation memory op = entryPoint.fillUserOp(
    //         address(kernel),
    //         abi.encodeWithSelector(
    //             KernelStorage.setDefaultValidator.selector,
    //             address(newValidator),
    //             empty
    //         )
    //     );
    //     op.signature = abi.encodePacked(
    //         bytes4(0x00000000),
    //         entryPoint.signUserOpHash(vm, ownerKey, op)
    //     );
    //     UserOperation[] memory ops = new UserOperation[](1);
    //     ops[0] = op;
    //     entryPoint.handleOps(ops, beneficiary);
    //     assertEq(
    //         address(KernelStorage(address(kernel)).getDefaultValidator()),
    //         address(newValidator)
    //     );
    // }

    // function test_disable_mode() external {
    //     bytes memory empty;
    //     UserOperation memory op = entryPoint.fillUserOp(
    //         address(kernel),
    //         abi.encodeWithSelector(
    //             KernelStorage.disableMode.selector,
    //             bytes4(0x00000001),
    //             address(0),
    //             empty
    //         )
    //     );
    //     op.signature = abi.encodePacked(
    //         bytes4(0x00000000),
    //         entryPoint.signUserOpHash(vm, ownerKey, op)
    //     );
    //     UserOperation[] memory ops = new UserOperation[](1);
    //     ops[0] = op;
    //     entryPoint.handleOps(ops, beneficiary);
    //     assertEq(
    //         uint256(bytes32(KernelStorage(address(kernel)).getDisabledMode())),
    //         1 << 224
    //     );
    // }

    // function test_set_execution() external {
    //     TestValidator newValidator = new TestValidator();
    //     UserOperation memory op = entryPoint.fillUserOp(
    //         address(kernel),
    //         abi.encodeWithSelector(
    //             KernelStorage.setExecution.selector,
    //             bytes4(0xdeadbeef),
    //             address(0xdead),
    //             address(newValidator),
    //             uint48(0),
    //             uint48(0),
    //             bytes("")
    //         )
    //     );
    //     op.signature = abi.encodePacked(
    //         bytes4(0x00000000),
    //         entryPoint.signUserOpHash(vm, ownerKey, op)
    //     );
    //     UserOperation[] memory ops = new UserOperation[](1);
    //     ops[0] = op;
    //     entryPoint.handleOps(ops, beneficiary);
    //     ExecutionDetail memory execution = KernelStorage(address(kernel))
    //         .getExecution(bytes4(0xdeadbeef));
    //     assertEq(execution.executor, address(0xdead));
    //     assertEq(address(execution.validator), address(newValidator));
    //     assertEq(uint256(execution.validUntil), uint256(0));
    //     assertEq(uint256(execution.validAfter), uint256(0));
    // }

    // function test_set_execution2() external {
    //     TestValidator newValidator = new TestValidator();
    //     UserOperation memory op = entryPoint.fillUserOp(
    //         address(kernel),
    //         abi.encodeWithSelector(
    //             KernelStorage.setExecution.selector,
    //             bytes4(0xdeadbeef),
    //             address(0xdead),
    //             address(newValidator),
    //             uint48(0),
    //             uint48(0),
    //             bytes("")
    //         )
    //     );
    //     op.signature = abi.encodePacked(
    //         bytes4(0x00000000),
    //         entryPoint.signUserOpHash(vm, ownerTwoKey, op)
    //     );
    //     UserOperation[] memory ops = new UserOperation[](1);
    //     ops[0] = op;
    //     entryPoint.handleOps(ops, beneficiary);
    //     ExecutionDetail memory execution = KernelStorage(address(kernel))
    //         .getExecution(bytes4(0xdeadbeef));
    //     assertEq(execution.executor, address(0xdead));
    //     assertEq(address(execution.validator), address(newValidator));
    //     assertEq(uint256(execution.validUntil), uint256(0));
    //     assertEq(uint256(execution.validAfter), uint256(0));
    // }

    // function test_set_execution3() external {
    //     TestValidator newValidator = new TestValidator();
    //     UserOperation memory op = entryPoint.fillUserOp(
    //         address(kernel),
    //         abi.encodeWithSelector(
    //             KernelStorage.setExecution.selector,
    //             bytes4(0xdeadbeef),
    //             address(0xdead),
    //             address(newValidator),
    //             uint48(0),
    //             uint48(0),
    //             bytes("")
    //         )
    //     );
    //     op.signature = abi.encodePacked(
    //         bytes4(0x00000000),
    //         entryPoint.signUserOpHash(vm, randomKey, op)
    //     );
    //     UserOperation[] memory ops = new UserOperation[](1);
    //     ops[0] = op;
    //     vm.expectRevert();
    //     entryPoint.handleOps(ops, beneficiary);
    // }
}
