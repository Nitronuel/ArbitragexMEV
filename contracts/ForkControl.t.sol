// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/// Control experiment: replay a KNOWN-GOOD live call verbatim on fork.
///  - If it SUCCEEDS: the fork/env is sound; our built triple is at fault.
///  - If it REVERTS: the fork setup itself is broken (wrong block, state,
///    or router address), and all sweep negatives are meaningless.
contract ForkControl is Test {
    address constant ROUTER = 0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc;

    function test_replay_live_3leg() public {
        vm.createSelectFork(vm.envString("CHAINSTACK_RHC_HTTP_URL"));
        // Input of 0xb98fd3… (status=1 on-chain, 3 legs, venues 27/1/1).
        bytes memory cd = vm.parseBytes(
            vm.readFile("testdata/live3leg-input.txt")
        );
        address sender = 0x5a83bD9c6E8225020Bda6b050119884511306858;
        vm.prank(sender);
        (bool ok, bytes memory ret) = ROUTER.call(cd);
        console.log(ok ? "REPLAY OK" : "REPLAY REVERT");
        if (!ok) {
            console.logBytes(ret);
        }
    }
}
