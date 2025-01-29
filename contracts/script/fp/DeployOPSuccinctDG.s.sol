// SPDX-License-Identifier: MIT
pragma solidity 0.8.15;

import {Script} from "forge-std/Script.sol";
import {console} from "forge-std/console.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {DisputeGameFactory} from "src/dispute/DisputeGameFactory.sol";
import {OPSuccinctFaultDisputeGame} from "src/fp/OPSuccinctFaultDisputeGame.sol";
import {SP1MockVerifier} from "@sp1-contracts/src/SP1MockVerifier.sol";
import {Claim, GameType, Hash, OutputRoot, Duration} from "src/dispute/lib/Types.sol";
import {IDisputeGame} from "src/dispute/interfaces/IDisputeGame.sol";
import {IDisputeGameFactory} from "src/dispute/interfaces/IDisputeGameFactory.sol";
import {ISP1Verifier} from "@sp1-contracts/src/ISP1Verifier.sol";

contract DeployOPSuccinctDG is Script {
    function run() public {
        vm.startBroadcast();

        // Deploy the factory implementation
        DisputeGameFactory factoryImpl = new DisputeGameFactory();

        // Deploy factory proxy
        ERC1967Proxy factoryProxy = new ERC1967Proxy(
            address(factoryImpl), abi.encodeWithSelector(DisputeGameFactory.initialize.selector, msg.sender)
        );
        DisputeGameFactory factory = DisputeGameFactory(address(factoryProxy));

        // Setup starting anchor roots
        GameType gameType = GameType.wrap(uint32(vm.envUint("GAME_TYPE")));

        // Deploy SP1 mock verifier
        SP1MockVerifier sp1Verifier = new SP1MockVerifier();

        // Deploy game implementation
        uint64 maxChallengeDuration = uint64(vm.envUint("MAX_CHALLENGE_DURATION"));
        uint64 maxProveDuration = uint64(vm.envUint("MAX_PROVE_DURATION"));
        bytes32 rollupConfigHash = bytes32(0);
        bytes32 aggregationVkey = bytes32(0);
        bytes32 rangeVkeyCommitment = bytes32(0);
        uint256 genesisL2BlockNumber = uint256(0);
        bytes32 genesisL2OutputRoot = bytes32(0);
        uint256 proofReward = 0.01 ether;

        OPSuccinctFaultDisputeGame gameImpl = new OPSuccinctFaultDisputeGame(
            Duration.wrap(maxChallengeDuration),
            Duration.wrap(maxProveDuration),
            IDisputeGameFactory(address(factory)),
            ISP1Verifier(address(sp1Verifier)),
            rollupConfigHash,
            aggregationVkey,
            rangeVkeyCommitment,
            genesisL2BlockNumber,
            genesisL2OutputRoot,
            proofReward
        );

        // Set initial bond and implementation in factory
        factory.setInitBond(gameType, 0.01 ether);
        factory.setImplementation(gameType, IDisputeGame(address(gameImpl)));

        vm.stopBroadcast();

        // Log deployed addresses
        console.log("Factory Proxy:", address(factoryProxy));
        console.log("Game Implementation:", address(gameImpl));
        console.log("SP1 Verifier:", address(sp1Verifier));
    }
}
