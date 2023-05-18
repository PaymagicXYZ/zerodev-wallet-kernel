pragma solidity ^0.8.0;

import "src/factory/ECDSAKernelFactory.sol";
import "forge-std/Script.sol";
import "src/factory/KernelFactory.sol";
import "src/validator/ECDSAValidator.sol";

contract DeployKernel is Script {
    KernelFactory kernelFactory =
        KernelFactory(0xfE92bC93548568DDfe2f5A0d94840CE6Aa0718Ac);

    ECDSAValidator ecdsaValidator =
        ECDSAValidator(0x12085cc300d5eD7E1A0A36E55F70e64f0CAe1D2D);

    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        ECDSAKernelFactory factory = new ECDSAKernelFactory(
            kernelFactory,
            ecdsaValidator
        );
        vm.stopBroadcast();
    }
}
