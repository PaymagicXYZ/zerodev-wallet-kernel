// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

import "./MKernelFactory.sol";
import "src/validator/MECDSAValidator.sol";

contract MultiECDSAKernelFactory {
    MKernelFactory public immutable singletonFactory;
    MECDSAValidator public immutable validator;
    IEntryPoint public immutable entryPoint;

    constructor(
        MKernelFactory _singletonFactory,
        MECDSAValidator _validator,
        IEntryPoint _entryPoint
    ) {
        singletonFactory = _singletonFactory;
        validator = _validator;
        entryPoint = _entryPoint;
    }

    function createAccount(
        uint256 _index
    ) external returns (EIP1967Proxy proxy) {
        proxy = singletonFactory.createAccount(validator, _index);
    }

    function getAccountAddress(uint256 _index) public view returns (address) {
        return singletonFactory.getAccountAddress(validator, data, _index);
    }
}
