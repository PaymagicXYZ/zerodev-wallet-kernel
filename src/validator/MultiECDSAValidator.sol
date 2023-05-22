// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./IValidator.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import "src/utils/KernelHelper.sol";

struct MultiOwnerValidatorStorage {
    mapping(address => bool) owners;
}

contract MultiECDSAValidator is IKernelValidator {
    mapping(address => MultiOwnerValidatorStorage) multiOwnerValidatorStorage;

    event OwnerAdded(address indexed kernel, address indexed owner);
    event OwnerRemoved(address indexed kernel, address indexed owner);

    function enable(bytes calldata _data) external override {
        address[] memory owners = abi.decode(_data, (address[]));
        for (uint256 i = 0; i < owners.length; i++) {
            multiOwnerValidatorStorage[msg.sender].owners[owners[i]] = true;
            emit OwnerAdded(msg.sender, owners[i]);
        }
    }

    function disable(bytes calldata _data) external override {
        address[] memory owners = abi.decode(_data, (address[]));
        for (uint256 i = 0; i < owners.length; i++) {
            delete multiOwnerValidatorStorage[msg.sender].owners[owners[i]];
            emit OwnerRemoved(msg.sender, owners[i]);
        }
    }

    function isOwner(address kernel, address owner) public view returns (bool) {
        return multiOwnerValidatorStorage[kernel].owners[owner];
    }

    function validateUserOp(
        UserOperation calldata _userOp,
        bytes32 _userOpHash,
        uint256
    ) external view override returns (uint256 validationData) {
        address recovered = ECDSA.recover(_userOpHash, _userOp.signature);
        if (isOwner(_userOp.sender, recovered)) {
            return 0;
        }
        bytes32 hash = ECDSA.toEthSignedMessageHash(_userOpHash);
        recovered = ECDSA.recover(hash, _userOp.signature);
        if (!isOwner(_userOp.sender, recovered)) {
            return SIG_VALIDATION_FAILED;
        }
    }

    function validateSignature(
        bytes32 hash,
        bytes calldata signature
    ) public view override returns (uint256) {
        address recovered = ECDSA.recover(hash, signature);
        if (isOwner(msg.sender, recovered)) {
            return 0;
        } else {
            return 1;
        }
    }
}
