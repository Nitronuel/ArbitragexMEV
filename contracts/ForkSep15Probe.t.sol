// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./ExecutorV4Morpho.sol";
import "forge-std/Test.sol";
import "forge-std/console.sol";

/// One-shot probe (delete after use): replay the 5 WETH/0x5691 rows from
/// 2026-09-14/15 that reverted ProfitTooLow live, with minProfit=0, on a
/// fork pinned at each row's detection block. Measures true executable
/// profit + gas to adjudicate whether a 2x-gas on-chain bar would execute.
contract ForkSep15Probe is Test {
    address constant EXEC = 0x727f41B647e9F0958dd539b0dFff4fc46A90A950;
    address constant WETH = 0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73;
    address constant TKN = 0x56910D4409F3a0C78C64DD8D0545FF0705389870;
    address constant V3POOL = 0x2a55F1415A26b5612e7C9A401A862d0692F3D1Db;
    address constant PM = 0x8366a39CC670B4001A1121B8F6A443A643e40951;
    bytes32 constant V4POOLID =
        0x00dd2df2f17d431cf3a0938f06c9cf9abc5e9643b6cc466ca3f71f3af246edf3;
    // v4-overrides.csv for the V4 pool above.
    address constant HOOKS = 0x2cD91bD228ff4c537031d6b8204782090c84c0cC;

    function _probe(uint256 blk, uint256 input, uint256 quoted) internal {
        vm.createSelectFork("rhc", blk);
        address owner = ExecutorV4Morpho(payable(EXEC)).owner();
        vm.deal(owner, 10 ether);
        RouteLeg[] memory legs = new RouteLeg[](2);
        legs[0] = RouteLeg({
            venue: 0,
            v3Pool: V3POOL,
            inTok: WETH,
            outTok: TKN,
            zeroForOne: true, // 0x0Bd7.. < 0x5691..: WETH is token0
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
                WETH, input, abi.encode(legs), 0
            )
        {
            uint256 profit = IERC20(WETH).balanceOf(owner) - b0;
            uint256 gasUsed = vm.lastCallGas().gasTotalUsed;
            console.log("block:");
            console.logUint(blk);
            console.log("EXECUTED profitWei:");
            console.logUint(profit);
            console.log("quotedWei:");
            console.logUint(quoted);
            console.log("gasUsed:");
            console.logUint(gasUsed);
        } catch (bytes memory err) {
            bytes4 sel;
            assembly {
                sel := mload(add(err, 32))
            }
            console.log("block:");
            console.logUint(blk);
            console.log("REVERT:");
            console.logBytes4(sel);
        }
    }

    function test_row_63204847() public {
        _probe(63204847, 13519828624074453, 155637058643765);
    }

    function test_row_63217628() public {
        _probe(63217628, 12951701309655210, 145121422566957);
    }

    function test_row_63258682() public {
        _probe(63258682, 18207324175411491, 290075079349243);
    }

    function test_row_63259019() public {
        _probe(63259019, 16466864684098351, 236987187451985);
    }

    function test_row_63261296() public {
        _probe(63261296, 32829968883422493, 133716812281216);
    }
}
