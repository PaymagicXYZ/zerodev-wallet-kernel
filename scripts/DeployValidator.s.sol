pragma solidity ^0.8.0;

import "src/validator/ECDSAValidator.sol";
import "forge-std/Script.sol";

contract DeployKernel is Script {
    function run() public {
        uint256 key = vm.envUint("DEPLOYER_PRIVATE_KEY");
        vm.startBroadcast(key);
        ECDSAValidator validator = new ECDSAValidator();
        vm.stopBroadcast();
    }
}
