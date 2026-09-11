// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./ExecutorV4Morpho.sol";
import "forge-std/Test.sol";
import "forge-std/console.sol";

/// Fork probe: rotated USDG-anchored triangle execution against REAL Blue +
/// REAL router + REAL pools on RHC (chain 4663).
///
/// Detected (anchor-first) cycle, quoted net ~$48 at block 55716635:
///   leg0 V3 RDDT->WNATIVE  pool 0xa54114… fee 10000
///   leg1 V3 WNATIVE->USDG  pool 0x52e65b… fee 100
///   leg2 V4 USDG->RDDT     pool c60d9f…   fee 2800 (tickSpacing/hooks UNKNOWN)
///
/// Rotation (same pools, USDG-anchored so Blue can fund it):
///   leg0 V4 USDG->RDDT, leg1 V3 RDDT->WNATIVE, leg2 V3 WNATIVE->USDG.
///
/// Verdict logic: the V4 leg is leg-0, so ANY flash amount reaches it
/// immediately. If a (tickSpacing, hooks) combo executes past leg-0, the
/// route is catchable (dies at ProfitTooLow or pays). If every combo reverts
/// inside the router call, the triangle is uncatchable via 0x4d819a2a.
///
/// Run (read-only, zero gas):
///   forge test --fork-url https://rpc.mainnet.chain.robinhood.com \
///     --match-contract TriangleReanchorForkTest -vv
contract TriangleReanchorForkTest is Test {
    ExecutorV4Morpho public executor;

    address constant USDG = 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168;
    address constant RDDT = 0x05b37Fb53A299a1b874A619e1c4C404D52C36F4C;
    address constant WNATIVE = 0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73;
    address constant V3_A = 0xA541143F20D7b0643123064aBF25F423E375b531; // RDDT->WNATIVE 10000
    address constant V3_B = 0x52e65B17fB6E5BA00Ed806f37Afcd2DaA50271Ca; // WNATIVE->USDG 100
    uint24 constant V4_FEE = 2800;

    function setUp() public {
        executor = new ExecutorV4Morpho();
    }

    function _v3leg(address pool, address inTok, address outTok, bool zfo, uint24 fee)
        internal pure returns (RouteLeg memory)
    {
        return RouteLeg({
            venue: 0, v3Pool: pool, inTok: inTok, outTok: outTok,
            zeroForOne: zfo, sqrtPriceLimitX96: 0, fee: fee,
            tickSpacing: 0, hooks: address(0), hookData: "",
            pool: address(0), poolKey: bytes32(0)
        });
    }

    function _v4leg(address inTok, address outTok, int24 tick, address hooks)
        internal pure returns (RouteLeg memory)
    {
        return RouteLeg({
            venue: 1, v3Pool: address(0), inTok: inTok, outTok: outTok,
            zeroForOne: false, sqrtPriceLimitX96: 0, fee: V4_FEE,
            tickSpacing: tick, hooks: hooks, hookData: "",
            pool: address(0), poolKey: bytes32(0)
        });
    }

    function test_rotated_triangle_param_probe() public {
        if (block.chainid != 4663) return; // requires the RHC fork
        // Blue must fund the rotated entry (~2500 USDG; holds ~44M).
        (bool balOk, bytes memory balRet) = USDG.staticcall(
            abi.encodeWithSelector(bytes4(keccak256("balanceOf(address)")), executor.MORPHO())
        );
        require(balOk, "blue balance read failed");
        uint256 blueBal = abi.decode(balRet, (uint256));
        console.log("blue USDG balance (base units):", blueBal);
        require(blueBal >= 2500e6, "blue cannot fund rotated entry");

        int24[7] memory ticks = [int24(1), int24(8), int24(10), int24(45), int24(50), int24(60), int24(200)];
        uint256 executed = 0;
        for (uint256 i = 0; i < ticks.length; i++) {
            RouteLeg[] memory legs = new RouteLeg[](3);
            legs[0] = _v4leg(USDG, RDDT, ticks[i], address(0));
            legs[1] = _v3leg(V3_A, RDDT, WNATIVE, true, 10000);
            legs[2] = _v3leg(V3_B, WNATIVE, USDG, true, 100);
            (bool ok, bytes memory ret) = address(executor).call(
                abi.encodeCall(
                    executor.executeMorphoHybrid, (USDG, 2500e6, abi.encode(legs), 0)
                )
            );
            if (ok) {
                executed++;
                console.log("tick", uint256(int256(ticks[i])), "EXECUTED (paid or profit-gated)");
            } else {
                bytes4 sel;
                if (ret.length >= 4) {
                    assembly { sel := mload(add(ret, 32)) }
                }
                console.log("tick", uint256(int256(ticks[i])), "reverted:");
                console.logBytes4(sel);
            }
        }
        console.log("combos executed past leg-0:", executed, "/ 7");
        assertTrue(true); // probe reports; verdict is read off the log
    }
}
