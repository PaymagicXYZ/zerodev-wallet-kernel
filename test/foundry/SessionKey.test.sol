// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "src/Kernel.sol";
import "src/validator/ECDSAValidator.sol";
import "src/factory/EIP1967Proxy.sol";
import "src/factory/KernelFactory.sol";
import "src/factory/ECDSAKernelFactory.sol";
// test artifacts
import "src/test/TestValidator.sol";
import "src/test/TestExecutor.sol";
import "src/test/TestERC721.sol";
// test utils
import "forge-std/Test.sol";
import {ERC4337Utils} from "./ERC4337Utils.sol";
// test actions/validators
import "src/validator/ERC165SessionKeyValidator.sol";
import "src/executor/TokenActions.sol";

using ERC4337Utils for EntryPoint;

contract SessionKeyTest is Test {
    Kernel kernel;
    KernelFactory factory;
    ECDSAKernelFactory ecdsaFactory;
    EntryPoint entryPoint;
    ECDSAValidator validator;
    address owner;
    uint256 ownerKey;
    address payable beneficiary;

    function setUp() public {
        (owner, ownerKey) = makeAddrAndKey("owner");
        entryPoint = new EntryPoint();
        factory = new KernelFactory(entryPoint);

        validator = new ECDSAValidator();
        ecdsaFactory = new ECDSAKernelFactory(factory, validator, entryPoint);

        kernel = Kernel(payable(address(ecdsaFactory.createAccount(owner, 0))));
        vm.deal(address(kernel), 1e30);
        beneficiary = payable(address(makeAddr("beneficiary")));
    }

    function test_mode_2_erc165() external {
        ERC165SessionKeyValidator sessionKeyValidator = new ERC165SessionKeyValidator();
        TokenActions action = new TokenActions();
        TestERC721 erc721 = new TestERC721();
        erc721.mint(address(kernel), 0);
        erc721.mint(address(kernel), 1);
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(
                TokenActions.transferERC721Action.selector,
                address(erc721),
                0,
                address(0xdead)
            )
        );
        address sessionKeyAddr;
        uint256 sessionKeyPriv;
        (sessionKeyAddr, sessionKeyPriv) = makeAddrAndKey("sessionKey");
        bytes memory enableData = abi.encodePacked(
            sessionKeyAddr,
            type(IERC721).interfaceId,
            TokenActions.transferERC721Action.selector,
            uint48(0),
            uint48(0),
            uint32(16)
        );
        {
            bytes32 digest = getTypedDataHash(
                address(kernel),
                TokenActions.transferERC721Action.selector,
                0,
                0,
                address(sessionKeyValidator),
                address(action),
                enableData
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);

            op.signature = abi.encodePacked(
                bytes4(0x00000002),
                uint48(0),
                uint48(0),
                address(sessionKeyValidator),
                address(action),
                uint256(enableData.length),
                enableData,
                uint256(65),
                r,
                s,
                v
            );
        }

        op.signature = bytes.concat(
            op.signature,
            entryPoint.signUserOpHash(vm, sessionKeyPriv, op)
        );

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        logGas(op);
        entryPoint.handleOps(ops, beneficiary);

        op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(
                TokenActions.transferERC721Action.selector,
                address(erc721),
                1,
                address(0xdead)
            )
        );
        op.signature = abi.encodePacked(
            bytes4(0x00000001),
            entryPoint.signUserOpHash(vm, sessionKeyPriv, op)
        );
        ops[0] = op;
        logGas(op);
        entryPoint.handleOps(ops, beneficiary);

        assertEq(erc721.ownerOf(0), address(0xdead));
    }

    function test_mode_2_erc165_replay() external {
        ERC165SessionKeyValidator sessionKeyValidator = new ERC165SessionKeyValidator();
        TokenActions action = new TokenActions();
        TestERC721 erc721 = new TestERC721();
        erc721.mint(address(kernel), 0);
        erc721.mint(address(kernel), 1);
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(
                TokenActions.transferERC721Action.selector,
                address(erc721),
                0,
                address(0xdead)
            )
        );
        address sessionKeyAddr;
        uint256 sessionKeyPriv;
        (sessionKeyAddr, sessionKeyPriv) = makeAddrAndKey("sessionKey");
        bytes memory enableData = abi.encodePacked(
            sessionKeyAddr,
            type(IERC721).interfaceId,
            TokenActions.transferERC721Action.selector,
            uint48(0),
            uint48(0),
            uint32(16)
        );
        {
            bytes32 digest = getTypedDataHash(
                address(kernel),
                TokenActions.transferERC721Action.selector,
                0,
                0,
                address(sessionKeyValidator),
                address(action),
                enableData
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);

            op.signature = abi.encodePacked(
                bytes4(0x00000002),
                uint48(0),
                uint48(0),
                address(sessionKeyValidator),
                address(action),
                uint256(enableData.length),
                enableData,
                uint256(65),
                r,
                s,
                v
            );
        }

        op.signature = bytes.concat(
            op.signature,
            entryPoint.signUserOpHash(vm, sessionKeyPriv, op)
        );

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        logGas(op);
        entryPoint.handleOps(ops, beneficiary);

        op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(
                TokenActions.transferERC721Action.selector,
                address(erc721),
                1,
                address(0xdead)
            )
        );
        op.signature = abi.encodePacked(
            bytes4(0x00000001),
            entryPoint.signUserOpHash(vm, sessionKeyPriv, op)
        );
        ops[0] = op;
        logGas(op);
        entryPoint.handleOps(ops, beneficiary);

        assertEq(erc721.ownerOf(0), address(0xdead));

        vm.prank(address(0xdead));
        erc721.transferFrom(address(0xdead), address(kernel), 0);

        vm.expectRevert();
        entryPoint.handleOps(ops, beneficiary);
    }

    function test_mode_2_erc165_invalid_session_key() external {
        ERC165SessionKeyValidator sessionKeyValidator = new ERC165SessionKeyValidator();
        TokenActions action = new TokenActions();
        TestERC721 erc721 = new TestERC721();
        erc721.mint(address(kernel), 0);
        erc721.mint(address(kernel), 1);
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(
                TokenActions.transferERC721Action.selector,
                address(erc721),
                0,
                address(0xdead)
            )
        );
        address sessionKeyAddr;
        uint256 sessionKeyPriv;
        (sessionKeyAddr, sessionKeyPriv) = makeAddrAndKey("invalidSessionKey");
        bytes memory enableData = abi.encodePacked(
            sessionKeyAddr,
            type(IERC721).interfaceId,
            TokenActions.transferERC721Action.selector,
            uint48(0),
            uint48(0),
            uint32(16)
        );
        {
            bytes32 digest = getTypedDataHash(
                address(kernel),
                TokenActions.transferERC721Action.selector,
                0,
                0,
                address(sessionKeyValidator),
                address(action),
                enableData
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);

            op.signature = abi.encodePacked(
                bytes4(0x00000002),
                uint48(0),
                uint48(0),
                address(sessionKeyValidator),
                address(action),
                uint256(enableData.length),
                enableData,
                uint256(65),
                r,
                s,
                v
            );
        }

        op.signature = bytes.concat(
            op.signature,
            entryPoint.signUserOpHash(vm, sessionKeyPriv, op)
        );

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        logGas(op);

        entryPoint.handleOps(ops, beneficiary);
    }

    //i want to transfer Id 1 to 0xdead
    function test_mode_2_erc165_invalid_token_id() external {
        ERC165SessionKeyValidator sessionKeyValidator = new ERC165SessionKeyValidator();
        TokenActions action = new TokenActions();
        TestERC721 erc721 = new TestERC721();
        erc721.mint(address(kernel), 0);
        erc721.mint(address(kernel), 1);
        UserOperation memory op0 = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(
                TokenActions.transferERC721Action.selector,
                address(erc721),
                0,
                address(0xdead)
            )
        );
        UserOperation memory op1 = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(
                TokenActions.transferERC721Action.selector,
                address(erc721),
                1,
                address(0xdead)
            )
        );
        address sessionKeyAddr;
        uint256 sessionKeyPriv;
        (sessionKeyAddr, sessionKeyPriv) = makeAddrAndKey("sessionKey");
        bytes memory enableData = abi.encodePacked(
            sessionKeyAddr,
            type(IERC721).interfaceId,
            TokenActions.transferERC721Action.selector,
            uint48(0),
            uint48(0),
            uint32(16)
        );
        {
            bytes32 digest = getTypedDataHash(
                address(kernel),
                TokenActions.transferERC721Action.selector,
                0,
                0,
                address(sessionKeyValidator),
                address(action),
                enableData
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);

            op0.signature = abi.encodePacked(
                bytes4(0x00000002),
                uint48(0),
                uint48(0),
                address(sessionKeyValidator),
                address(action),
                uint256(enableData.length),
                enableData,
                uint256(65),
                r,
                s,
                v
            );
        }

        op0.signature = bytes.concat(
            op0.signature,
            entryPoint.signUserOpHash(vm, sessionKeyPriv, op0)
        );

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op0;
        logGas(op0);

        entryPoint.handleOps(ops, beneficiary);

        assertEq(erc721.ownerOf(0), address(0xdead));
    }

    function test_mode_2_erc165_invalid_owner() external {
        ERC165SessionKeyValidator sessionKeyValidator = new ERC165SessionKeyValidator();
        TokenActions action = new TokenActions();
        TestERC721 erc721 = new TestERC721();
        erc721.mint(address(kernel), 0);
        erc721.mint(address(kernel), 1);
        UserOperation memory op = entryPoint.fillUserOp(
            address(kernel),
            abi.encodeWithSelector(
                TokenActions.transferERC721Action.selector,
                address(erc721),
                0,
                address(0xdead)
            )
        );
        address sessionKeyAddr;
        uint256 sessionKeyPriv;
        (sessionKeyAddr, sessionKeyPriv) = makeAddrAndKey("invalidOwner");
        bytes memory enableData = abi.encodePacked(
            sessionKeyAddr,
            type(IERC721).interfaceId,
            TokenActions.transferERC721Action.selector,
            uint48(0),
            uint48(0),
            uint32(16)
        );
        {
            bytes32 digest = getTypedDataHash(
                address(kernel),
                TokenActions.transferERC721Action.selector,
                0,
                0,
                address(sessionKeyValidator),
                address(action),
                enableData
            );
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerKey, digest);

            op.signature = abi.encodePacked(
                bytes4(0x00000002),
                uint48(0),
                uint48(0),
                address(sessionKeyValidator),
                address(action),
                uint256(enableData.length),
                enableData,
                uint256(65),
                r,
                s,
                v
            );
        }

        op.signature = bytes.concat(
            op.signature,
            entryPoint.signUserOpHash(vm, sessionKeyPriv, op)
        );

        UserOperation[] memory ops = new UserOperation[](1);
        ops[0] = op;
        logGas(op);
        // vm.expectRevert();
        entryPoint.handleOps(ops, beneficiary);

        assertEq(erc721.ownerOf(0), address(0xdead));
    }

    function logGas(UserOperation memory op) internal returns (uint256 used) {
        try this.consoleGasUsage(op) {
            revert("should revert");
        } catch Error(string memory reason) {
            used = abi.decode(bytes(reason), (uint256));
            console.log("validation gas usage :", used);
        }
    }

    function consoleGasUsage(UserOperation memory op) external {
        uint256 gas = gasleft();
        vm.startPrank(address(entryPoint));
        kernel.validateUserOp(op, entryPoint.getUserOpHash(op), 0);
        vm.stopPrank();
        revert(string(abi.encodePacked(gas - gasleft())));
    }
}

// computes the hash of a permit
function getStructHash(
    bytes4 sig,
    uint48 validUntil,
    uint48 validAfter,
    address validator,
    address executor,
    bytes memory enableData
) pure returns (bytes32) {
    return
        keccak256(
            abi.encode(
                keccak256(
                    "ValidatorApproved(bytes4 sig,uint256 validatorData,address executor,bytes enableData)"
                ),
                bytes4(sig),
                uint256(
                    uint256(uint160(validator)) |
                        (uint256(validAfter) << 160) |
                        (uint256(validUntil) << (48 + 160))
                ),
                executor,
                keccak256(enableData)
            )
        );
}

// computes the hash of the fully encoded EIP-712 message for the domain, which can be used to recover the signer
function getTypedDataHash(
    address sender,
    bytes4 sig,
    uint48 validUntil,
    uint48 validAfter,
    address validator,
    address executor,
    bytes memory enableData
) view returns (bytes32) {
    return
        keccak256(
            abi.encodePacked(
                "\x19\x01",
                _buildDomainSeparator("Kernel", "0.0.2", sender),
                getStructHash(
                    sig,
                    validUntil,
                    validAfter,
                    validator,
                    executor,
                    enableData
                )
            )
        );
}

function _buildDomainSeparator(
    string memory name,
    string memory version,
    address verifyingContract
) view returns (bytes32) {
    bytes32 hashedName = keccak256(bytes(name));
    bytes32 hashedVersion = keccak256(bytes(version));
    bytes32 typeHash = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    return
        keccak256(
            abi.encode(
                typeHash,
                hashedName,
                hashedVersion,
                block.chainid,
                address(verifyingContract)
            )
        );
}

// pragma solidity ^0.8.0;

// // Importing external libraries and contracts
// import "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
// import "account-abstraction/core/Helpers.sol";
// import "account-abstraction/interfaces/IAccount.sol";
// import "account-abstraction/interfaces/IEntryPoint.sol";
// import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
// import "./utils/Exec.sol";
// import "./abstract/Compatibility.sol";
// import "./abstract/KernelStorage.sol";
// import "./utils/KernelHelper.sol";

// /// @title Kernel
// /// @author taek<leekt216@gmail.com>
// /// @notice wallet kernel for minimal wallet functionality
// contract Kernel is IAccount, EIP712, Compatibility, KernelStorage {
//     string public constant name = "Kernel";

//     string public constant version = "0.0.2";

//     /// @dev Sets up the EIP712 and KernelStorage with the provided entry point
//     constructor(
//         IEntryPoint _entryPoint
//     ) EIP712(name, version) KernelStorage(_entryPoint) {}

//     /// @notice Accepts incoming Ether transactions and calls from the EntryPoint contract
//     /// @dev This function will delegate any call to the appropriate executor based on the function signature.
//     fallback() external payable {
//         require(
//             msg.sender == address(entryPoint),
//             "account: not from entrypoint"
//         );
//         bytes4 sig = msg.sig;
//         address executor = getKernelStorage().execution[sig].executor;
//         assembly {
//             calldatacopy(0, 0, calldatasize())
//             let result := delegatecall(gas(), executor, 0, calldatasize(), 0, 0)
//             returndatacopy(0, 0, returndatasize())
//             switch result
//             case 0 {
//                 revert(0, returndatasize())
//             }
//             default {
//                 return(0, returndatasize())
//             }
//         }
//     }

//     /// @notice Executes a function call to an external contract
//     /// @dev The type of operation (call or delegatecall) is specified as an argument.
//     /// @param to The address of the target contract
//     /// @param value The amount of Ether to send
//     /// @param data The call data to be sent
//     /// @param operation The type of operation (call or delegatecall)
//     function execute(
//         address to,
//         uint256 value,
//         bytes calldata data,
//         Operation operation
//     ) external {
//         require(
//             msg.sender == address(entryPoint),
//             "account: not from entrypoint"
//         );
//         bool success;
//         bytes memory ret;
//         if (operation == Operation.DelegateCall) {
//             (success, ret) = Exec.delegateCall(to, data);
//         } else {
//             (success, ret) = Exec.call(to, value, data);
//         }
//         if (!success) {
//             assembly {
//                 revert(add(ret, 32), mload(ret))
//             }
//         }
//     }

//     /// @notice Validates a user operation based on its mode
//     /// @dev This function will validate user operation and be called by EntryPoint
//     /// @param userOp The user operation to be validated
//     /// @param userOpHash The hash of the user operation
//     /// @param missingAccountFunds The funds needed to be reimbursed
//     /// @return validationData The data used for validation
//     function validateUserOp(
//         UserOperation calldata userOp,
//         bytes32 userOpHash,
//         uint256 missingAccountFunds
//     ) external returns (uint256 validationData) {
//         require(
//             msg.sender == address(entryPoint),
//             "account: not from entryPoint"
//         );
//         // mode based signature
//         bytes4 mode = bytes4(userOp.signature[0:4]); // mode == 00..00 use validators
//         require(
//             mode & getKernelStorage().disabledMode == 0x00000000,
//             "kernel: mode disabled"
//         );
//         // mode == 0x00000000 use sudo validator
//         // mode == 0x00000001 use given validator
//         // mode == 0x00000002 enable validator
//         UserOperation memory op = userOp;
//         IKernelValidator validator;
//         bytes4 sig = bytes4(userOp.callData[0:4]);
//         if (mode == 0x00000000) {
//             // sudo mode (use default validator)
//             op = userOp;
//             op.signature = userOp.signature[4:];
//             validator = getKernelStorage().defaultValidator;
//         } else if (mode == 0x00000001) {
//             ExecutionDetail storage detail = getKernelStorage().execution[sig];
//             validator = detail.validator;
//             if (address(validator) == address(0)) {
//                 validator = getKernelStorage().defaultValidator;
//             }
//             op.signature = userOp.signature[4:];
//             validationData =
//                 (uint256(detail.validAfter) << 160) |
//                 (uint256(detail.validUntil) << (48 + 160));
//         } else if (mode == 0x00000002) {
//             // use given validator
//             // userOp.signature[4:10] = validUntil,
//             // userOp.signature[10:16] = validAfter,
//             // userOp.signature[16:36] = validator address,
//             validator = IKernelValidator(
//                 address(bytes20(userOp.signature[16:36]))
//             );
//             bytes calldata enableData;
//             bytes calldata remainSig;
//             (validationData, enableData, remainSig) = _approveValidator(
//                 sig,
//                 userOp.signature
//             );
//             validator.enable(enableData);
//             op.signature = remainSig;
//         } else {
//             return SIG_VALIDATION_FAILED;
//         }
//         if (missingAccountFunds > 0) {
//             // we are going to assume signature is valid at this point
//             (bool success, ) = msg.sender.call{value: missingAccountFunds}("");
//             (success);
//         }
//         validationData = _intersectValidationData(
//             validationData,
//             validator.validateUserOp(op, userOpHash, missingAccountFunds)
//         );
//         return validationData;
//     }

//     function _approveValidator(
//         bytes4 sig,
//         bytes calldata signature
//     )
//         internal
//         returns (
//             uint256 validationData,
//             bytes calldata enableData,
//             bytes calldata validationSig
//         )
//     {
//         uint256 enableDataLength = uint256(bytes32(signature[56:88]));
//         enableData = signature[88:88 + enableDataLength];
//         uint256 enableSignatureLength = uint256(
//             bytes32(signature[88 + enableDataLength:120 + enableDataLength])
//         );
//         bytes32 enableDigest = _hashTypedDataV4(
//             keccak256(
//                 abi.encode(
//                     keccak256(
//                         "ValidatorApproved(bytes4 sig,uint256 validatorData,address executor,bytes enableData)"
//                     ),
//                     bytes4(sig),
//                     uint256(bytes32(signature[4:36])),
//                     address(bytes20(signature[36:56])),
//                     keccak256(enableData)
//                 )
//             )
//         );
//         validationData = _intersectValidationData(
//             getKernelStorage().defaultValidator.validateSignature(
//                 enableDigest,
//                 signature[120 + enableDataLength:120 +
//                     enableDataLength +
//                     enableSignatureLength]
//             ),
//             uint256(bytes32(signature[4:36])) &
//                 (uint256(type(uint96).max) << 160)
//         );
//         validationSig = signature[120 +
//             enableDataLength +
//             enableSignatureLength:];
//         getKernelStorage().execution[sig] = ExecutionDetail({
//             executor: address(bytes20(signature[36:56])),
//             validator: IKernelValidator(address(bytes20(signature[16:36]))),
//             validUntil: uint48(bytes6(signature[4:10])),
//             validAfter: uint48(bytes6(signature[10:16]))
//         });
//         return (
//             validationData,
//             signature[88:88 + enableDataLength],
//             validationSig
//         );
//     }

//     /// @notice Checks if a signature is valid
//     /// @dev This function checks if a signature is valid based on the hash of the data signed.
//     /// @param hash The hash of the data that was signed
//     /// @param signature The signature to be validated
//     /// @return The magic value 0x1626ba7e if the signature is valid, otherwise returns 0xffffffff.
//     function isValidSignature(
//         bytes32 hash,
//         bytes calldata signature
//     ) external view returns (bytes4) {
//         uint256 validationData = getKernelStorage()
//             .defaultValidator
//             .validateSignature(hash, signature);
//         ValidationData memory data = _parseValidationData(validationData);
//         if (data.validAfter > block.timestamp) {
//             return 0xffffffff;
//         }
//         if (data.validUntil < block.timestamp) {
//             return 0xffffffff;
//         }
//         if (data.aggregator != address(0)) {
//             return 0xffffffff;
//         }

//         return 0x1626ba7e;
//     }
// }

// pragma solidity ^0.8.0;

// import "./IValidator.sol";
// import "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
// import "src/utils/KernelHelper.sol";
// import "account-abstraction/core/Helpers.sol";

// struct SessionKeyStorage {
//     uint48 validUntil;
//     uint48 validAfter;
// }

// contract SessionKeyOwnedValidator is IKernelValidator {
//     event OwnerChanged(
//         address indexed kernel,
//         address indexed oldOwner,
//         address indexed newOwner
//     );

//     mapping(address sessionKey => mapping(address kernel => SessionKeyStorage))
//         public sessionKeyStorage;

//     function disable(bytes calldata _data) external override {
//         address sessionKey = address(bytes20(_data[0:20]));
//         delete sessionKeyStorage[sessionKey][msg.sender];
//     }

//     function enable(bytes calldata _data) external override {
//         address sessionKey = address(bytes20(_data[0:20]));
//         uint48 validUntil = uint48(bytes6(_data[20:26]));
//         uint48 validAfter = uint48(bytes6(_data[26:32]));
//         require(
//             validUntil > validAfter,
//             "SessionKeyOwnedValidator: invalid validUntil/validAfter"
//         ); // we do not allow validUntil == 0 here use validUntil == 2**48-1 instead
//         sessionKeyStorage[sessionKey][msg.sender] = SessionKeyStorage(
//             validUntil,
//             validAfter
//         );
//     }

//     function validateUserOp(
//         UserOperation calldata _userOp,
//         bytes32 _userOpHash,
//         uint256
//     ) external view override returns (uint256 validationData) {
//         bytes32 hash = ECDSA.toEthSignedMessageHash(_userOpHash);
//         address recovered = ECDSA.recover(hash, _userOp.signature);

//         SessionKeyStorage storage sessionKey = sessionKeyStorage[recovered][
//             msg.sender
//         ];
//         if (sessionKey.validUntil == 0) {
//             // we do not allow validUntil == 0 here
//             return SIG_VALIDATION_FAILED;
//         }
//         return
//             _packValidationData(
//                 false,
//                 sessionKey.validUntil,
//                 sessionKey.validAfter
//             );
//     }

//     function validateSignature(
//         bytes32 hash,
//         bytes calldata signature
//     ) public view override returns (uint256) {
//         bytes32 ethhash = ECDSA.toEthSignedMessageHash(hash);
//         address recovered = ECDSA.recover(ethhash, signature);

//         SessionKeyStorage storage sessionKey = sessionKeyStorage[recovered][
//             msg.sender
//         ];
//         if (sessionKey.validUntil == 0) {
//             // we do not allow validUntil == 0 here
//             return SIG_VALIDATION_FAILED;
//         }
//         return
//             _packValidationData(
//                 false,
//                 sessionKey.validUntil,
//                 sessionKey.validAfter
//             );
//     }
// }
