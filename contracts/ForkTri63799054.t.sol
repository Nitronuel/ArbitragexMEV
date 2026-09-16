// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./ExecutorV4Morpho.sol";
import "forge-std/Test.sol";
import "forge-std/console.sol";

/// One-shot (delete after use): trace the first-ever triangle gate
/// (blk 63799054, WETH->0x39dB->USDG->WETH, all-V3) that reverted with EMPTY
/// data on estimate under the new bar. Latest fork is fine (no archive).
contract ForkTri63799054 is Test {
    address constant EXEC = 0x727f41B647e9F0958dd539b0dFff4fc46A90A950;
    address constant WETH = 0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73;
    address constant TKN = 0x39dBED3a2bd333467115dE45665cC57F813C4571;
    address constant USDG = 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168;
    address constant V3A = 0x544e1492315f24ec61C2A500a1C75e55E5bb20EB;
    address constant V3B = 0xf2A0bE59AB76b96f957bd5E5b967F2B75e8dB269;
    address constant V3C = 0x7A35168956F129c032eC035cC47383A605a71dF0;

    function test_trace() public {
        vm.createSelectFork("rhc");
        address owner = ExecutorV4Morpho(payable(EXEC)).owner();
        vm.deal(owner, 10 ether);
        RouteLeg[] memory legs = new RouteLeg[](3);
        legs[0] = RouteLeg({
            venue: 0, v3Pool: V3A, inTok: WETH, outTok: TKN,
            zeroForOne: true, sqrtPriceLimitX96: 0, fee: 1000,
            tickSpacing: 0, hooks: address(0), hookData: "",
            pool: address(0), poolKey: bytes32(0)
        });
        legs[1] = RouteLeg({
            venue: 0, v3Pool: V3B, inTok: TKN, outTok: USDG,
            zeroForOne: true, sqrtPriceLimitX96: 0, fee: 1000,
            tickSpacing: 0, hooks: address(0), hookData: "",
            pool: address(0), poolKey: bytes32(0)
        });
        legs[2] = RouteLeg({
            venue: 0, v3Pool: V3C, inTok: USDG, outTok: WETH,
            zeroForOne: false, sqrtPriceLimitX96: 0, fee: 40,
            tickSpacing: 0, hooks: address(0), hookData: "",
            pool: address(0), poolKey: bytes32(0)
        });
        vm.prank(owner);
        try ExecutorV4Morpho(payable(EXEC)).executeMorphoHybrid(
            WETH, 48676504425564269, abi.encode(legs), 0
        ) {
            console.log("EXECUTED");
        } catch (bytes memory err) {
            console.log("REVERT len:");
            console.logUint(err.length);
            if (err.length >= 4) {
                bytes4 sel;
                assembly { sel := mload(add(err, 32)) }
                console.logBytes4(sel);
            }
        }
    }
}
