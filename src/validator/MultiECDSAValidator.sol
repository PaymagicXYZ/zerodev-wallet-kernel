// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./IValidator.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";
import "openzeppelin-contracts/contracts/access/Ownable.sol";
import "src/utils/KernelHelper.sol";

contract MultiECDSAValidator is IKernelValidator, Ownable {
    event OwnerChanged(
        address indexed kernel,
        address indexed oldOwner,
        address indexed newOwner
    );

    constructor() {
        isOwner[msg.sender] = true;
    }

    mapping(address => bool) public isOwner;
    mapping(address => bool) public isValidator;

    function disable(bytes calldata) external override {
        isValidator[msg.sender] = false;
    }

    function enable(bytes calldata _data) external override {
        isValidator[msg.sender] = true;
        // emit OwnerChanged(msg.sender, oldOwner, owner);
    }

    function validateUserOp(
        UserOperation calldata _userOp,
        bytes32 _userOpHash,
        uint256
    ) external view override returns (uint256 validationData) {
        address recovered = ECDSA.recover(_userOpHash, _userOp.signature);
        if (isOwner[recovered] && isValidator[_userOp.sender]) {
            return 0;
        }
        bytes32 hash = ECDSA.toEthSignedMessageHash(_userOpHash);
        recovered = ECDSA.recover(hash, _userOp.signature);
        if (!isOwner[_userOp.sender] || !isValidator[msg.sender]) {
            return SIG_VALIDATION_FAILED;
        }
    }

    function validateSignature(
        bytes32 hash,
        bytes calldata signature
    ) public view override returns (uint256) {
        address recovered = ECDSA.recover(hash, signature);
        if (isOwner[recovered]) {
            return 0;
        } else {
            return 1;
        }
    }

    function addOwner(address _owner) external onlyOwner {
        isOwner[_owner] = true;
    }

    function removeOwner(address _owner) external onlyOwner {
        isOwner[_owner] = false;
    }
}
