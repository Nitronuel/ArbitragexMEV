// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./ExecutorV4Morpho.sol";
import "forge-std/Test.sol";
import "forge-std/console.sol";

/// INTERIM one-shot probe (delete after use): same legs/inputs as
/// ForkSep15Probe row 63258682 (largest quoted profit), but on a LATEST-block
/// fork with minProfit=0. Pinned-block forks are impossible right now
/// (Chainstack free = archive-gated -32002, Alchemy premium = 429 monthly
/// cap, public = 429). This tests STRUCTURAL executability only: if it
/// EXECUTEs, the route shape works and the 70% bar was the binding
/// constraint; any non-ProfitTooLow revert means 2x-gas would not have helped.
contract ForkSep15Live is Test {
    address constant EXEC = 0x727f41B647e9F0958dd539b0dFff4fc46A90A950;
    address constant WETH = 0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73;
    address constant TKN = 0x56910D4409F3a0C78C64DD8D0545FF0705389870;
    address constant V3POOL = 0x2a55F1415A26b5612e7C9A401A862d0692F3D1Db;
    address constant PM = 0x8366a39CC670B4001A1121B8F6A443A643e40951;
    bytes32 constant V4POOLID =
        0x00dd2df2f17d431cf3a0938f06c9cf9abc5e9643b6cc466ca3f71f3af246edf3;
    address constant HOOKS = 0x2cD91bD228ff4c537031d6b8204782090c84c0cC;

    function test_live_current_tip_minProfit0() public {
        _run(0);
    }

    /// New-bar mechanics check (approved 2026-09-15, pct=0 → floor binds):
    /// minProfit = ~$0.15 ≈ 2x gas at 0.07 gwei. Expects the SAME :216 path
    /// as minProfit=0 (loss-making now) — proves the only delta is the
    /// threshold number, no new revert paths.
    function test_live_current_tip_minProfit2xGas() public {
        _run(60_000_000_000_000);
    }

    function _run(uint256 minProfit) internal {
        vm.createSelectFork("rhc");
        uint256 input = 18207324175411491;
        address owner = ExecutorV4Morpho(payable(EXEC)).owner();
        vm.deal(owner, 10 ether);
        RouteLeg[] memory legs = new RouteLeg[](2);
        legs[0] = RouteLeg({
            venue: 0,
            v3Pool: V3POOL,
            inTok: WETH,
            outTok: TKN,
            zeroForOne: true,
            sqrtPriceLimitX96: 0,
            fee: 10000,
            tickSpacing: 0,
            hooks: address(0),
            hookData: "",
            pool: address(0),
            poolKey: bytes32(0)
        });
        legs[1] = RouteLeg({
            venue: 1,
            v3Pool: address(0),
            inTok: TKN,
            outTok: address(0), // trade convention: 0x0 native sentinel for V4 keys
            zeroForOne: false,
            sqrtPriceLimitX96: 0,
            fee: 10000,
            tickSpacing: 200,
            hooks: HOOKS,
            hookData: "",
            pool: PM,
            poolKey: V4POOLID
        });
        uint256 b0 = IERC20(WETH).balanceOf(owner);
        vm.prank(owner);
        try
            ExecutorV4Morpho(payable(EXEC)).executeMorphoHybrid(
                WETH, input, abi.encode(legs), minProfit
            )
        {
            uint256 profit = IERC20(WETH).balanceOf(owner) - b0;
            uint256 gasUsed = vm.lastCallGas().gasTotalUsed;
            console.log("EXECUTED profitWei:");
            console.logUint(profit);
            console.log("gasUsed:");
            console.logUint(gasUsed);
        } catch (bytes memory err) {
            bytes4 sel;
            assembly {
                sel := mload(add(err, 32))
            }
            console.log("REVERT:");
            console.logBytes4(sel);
        }
    }
}
