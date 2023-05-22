// SPDX-License-Identifier: MIT
import "./MultiKernelFactory.sol";
import "src/validator/MultiECDSAValidator.sol";

contract MultiECDSAKernelFactory {
    MultiKernelFactory immutable singletonFactory;
    MultiECDSAValidator immutable validator;

    constructor(
        MultiKernelFactory _singletonFactory,
        MultiECDSAValidator _validator
    ) {
        singletonFactory = _singletonFactory;
        validator = _validator;
    }

    function createAccount(
        address[] calldata _owners,
        uint256 _index
    ) external returns (EIP1967Proxy proxy) {
        bytes memory data = abi.encode(_owners);
        proxy = singletonFactory.createAccount(validator, data, _index);
    }

    function getAccountAddress(
        address[] calldata _owners,
        uint256 _index
    ) public view returns (address) {
        bytes memory data = abi.encodePacked(_owners);
        return singletonFactory.getAccountAddress(validator, data, _index);
    }
}
