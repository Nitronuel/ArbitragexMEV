// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./ExecutorV4Morpho.sol";
import "forge-std/Test.sol";
import "forge-std/console.sol";

/// Fork pin for the 2026-09-07 row-2 miss (USDG/0xded852, net $4.22):
/// the V4 leg reverted `BAD_ARGS` at estimate with catalog fee 38000 while
/// recent Swap logs charge 38962 on every swap (28/28). This test replays
/// the exact route with the corrected fee against CURRENT mainnet state.
///
/// Discriminating outcomes (minProfit = 0):
/// - Success OR `ProfitTooLow` => the router found the pool and the legs
///   executed through real pools. PATH PROVEN (profitability at this size
///   is not asserted — only executability).
/// - `BAD_ARGS` (or anything else) => the key is still wrong; the trace
///   below the assertion shows which frame reverts.
contract ForkRow2Pin is Test {
    address constant EXEC = 0x727f41B647e9F0958dd539b0dFff4fc46A90A950;
    address constant USDG = 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168;
    address constant DED = 0xded852De9fe9bA9b6f27f39e8e81CF851A5C79cc;
    address constant V3POOL = 0xB67259525e4E5F1526B3A008848a6fE3C9744321;
    address constant ROUTER = 0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc;
    address constant PM = 0x8366a39CC670B4001A1121B8F6A443A643e40951;
    bytes32 constant V4POOLID =
        0x7159c43bcc3961cf25e85875cbfca5eb4294fb54ce7dd88047bc3559794d832f;

    struct REL {
        uint8 venue;
        address c0;
        address c1;
        address pool;
        uint24 fee;
        int24 tickSpacing;
        address hooks;
        bytes hookData;
        address pm;
        bytes32 poolKey;
    }

    /// Venue/arg sweep on the CERTAIN key (USDG,DED,38000,380,0 → 7159c4):
    /// if the upgraded impl renumbered venues or changed
    /// amountIn/minOut/deadline semantics, one combo proceeds past argument
    /// validation (any pool interaction or non-BAD_ARGS revert).
    function test_router_arg_sweep() public {
        vm.createSelectFork("rhc");
        // certain key components
        address c0 = USDG; // 0x5fc5.. < 0xded8..: sorted
        address c1 = DED;
        bytes32 key = 0x7159c43bcc3961cf25e85875cbfca5eb4294fb54ce7dd88047bc3559794d832f;
        deal(c0, address(this), 10e6);
        deal(c1, address(this), 10e6);
        uint8[4] memory venues = [uint8(0), uint8(1), uint8(2), uint8(3)];
        for (uint256 i = 0; i < 4; i++) {
            REL[] memory els = new REL[](1);
            els[0] = REL({
                venue: venues[i],
                c0: c0,
                c1: c1,
                pool: address(0),
                fee: 38000,
                tickSpacing: 380,
                hooks: address(0),
                hookData: "",
                pm: 0x8366a39CC670B4001A1121B8F6A443A643e40951,
                poolKey: key
            });
            IERC20(c0).approve(ROUTER, 1e6);
            (bool ok, bytes memory ret) = ROUTER.call(
                abi.encodeWithSelector(
                    bytes4(0x4d819a2a), els, address(this), uint256(1e6), uint256(1), uint256(0)
                )
            );
            console.log("venue sweep:");
            console.logUint(venues[i]);
            console.log(ok ? "OK" : "REVERT");
            if (!ok && ret.length >= 4) {
                bytes4 sel;
                assembly {
                    sel := mload(add(ret, 32))
                }
                console.logBytes4(sel);
            }
            IERC20(c0).approve(ROUTER, 0);
        }
    }

    function _mkEl(
        address c0,
        address c1,
        uint24 fee,
        int24 tick,
        bytes32 key
    ) internal pure returns (REL[] memory els) {
        els = _mkElFull(c0, c1, fee, tick, key, address(0));
    }

    function _mkElFull(
        address c0,
        address c1,
        uint24 fee,
        int24 tick,
        bytes32 key,
        address pool
    ) internal pure returns (REL[] memory els) {
        els = new REL[](1);
        els[0] = REL({
            venue: 2,
            c0: c0,
            c1: c1,
            pool: pool,
            fee: fee,
            tickSpacing: tick,
            hooks: address(0),
            hookData: "",
            pm: 0x8366a39CC670B4001A1121B8F6A443A643e40951,
            poolKey: key
        });
    }

    /// Direct router probes (no executor): which RouterEl shape gets PAST
    /// argument validation (any pool interaction frame) vs immediate BAD_ARGS?
    /// V1 = ours today (directional, poolKey 0). V2 = + explicit poolKey.
    /// V3 = sorted currencies, poolKey 0 (sells USDG->DED, key-existence only).
    function test_router_key_probes() public {
        vm.createSelectFork("rhc");
        uint256 amt = 1e6; // 1 USDG (6 dec)
        deal(USDG, address(this), amt * 10);
        deal(DED, address(this), amt * 10);
        // poolKey for (DED, USDG, 38962, 380, 0x0)
        bytes32 key = keccak256(
            abi.encode(DED, USDG, uint24(38962), int24(380), address(0))
        );
        console.log("computed key:");
        console.logBytes32(key);
        console.log("catalog key:");
        console.logBytes32(V4POOLID);
        _probe("V1", USDG, DED, amt, _mkEl(DED, USDG, 38962, 380, bytes32(0)));
        _probe("V2", USDG, DED, amt, _mkEl(DED, USDG, 38962, 380, key));
        // V3: SORTED currencies + TRUE key (38000/380/0) — sells USDG->DED.
        // If this reaches pool interaction, RouterEl currencies must be sorted.
        _probe("V3", USDG, DED, amt, _mkEl(USDG, DED, 38000, 380, bytes32(0)));
        // V4: sorted + TRUE key + LIVE deadline (contract hardcodes 0).
        // If V4 proceeds where V3 (deadline 0) died, deadline=0 is the bug.
        _probeDeadline(
            "V6",
            DED,
            amt,
            _mkEl(USDG, DED, 38000, 380, bytes32(0)),
            block.timestamp + 3600
        );
        // V5: sorted + TRUE key + pool=PM (V4 liquidity lives in the
        // singleton; new impl may reject pool=address(0)).
        _probeDeadline(
            "V5",
            USDG,
            amt,
            _mkElFull(
                USDG,
                DED,
                38000,
                380,
                0x7159c43bcc3961cf25e85875cbfca5eb4294fb54ce7dd88047bc3559794d832f,
                0x8366a39CC670B4001A1121B8F6A443A643e40951
            ),
            block.timestamp + 3600
        );
        // V6: DIRECTIONAL (c0=DED,c1=USDG) + poolKey = keccak of EXACT passed
        // order (f01674e2). If the impl requires poolKey == hash(inputs
        // as-given), V6 is the only consistent call — any non-BAD_ARGS
        // outcome (even PoolNotInitialized) proves the match rule.
        _probeDeadline(
            "V6",
            DED,
            amt,
            _mkElFull(
                DED,
                USDG,
                38962,
                380,
                0xf01674e2590150b7b3577d1c9e4887491374135a015179e7fc0365230374b958,
                0x8366a39CC670B4001A1121B8F6A443A643e40951
            ),
            block.timestamp + 3600
        );
    }

    function _probe(
        string memory tag,
        address fundTok,
        address,
        uint256 amt,
        REL[] memory els
    ) internal {
        _probeDeadline(tag, fundTok, amt, els, 0);
    }

    function _probeDeadline(
        string memory tag,
        address fundTok,
        uint256 amt,
        REL[] memory els,
        uint256 deadline
    ) internal {
        IERC20(fundTok).approve(ROUTER, amt);
        (bool ok, bytes memory ret) = ROUTER.call(
            abi.encodeWithSelector(
                bytes4(0x4d819a2a), els, address(this), amt, uint256(1), deadline
            )
        );
        console.log(tag);
        console.log(ok ? "OK" : "REVERT");
        if (!ok && ret.length >= 4) {
            bytes4 sel;
            assembly {
                sel := mload(add(ret, 32))
            }
            console.logBytes4(sel);
        }
        IERC20(fundTok).approve(ROUTER, 0);
    }

    function test_row2_reaches_settlement_with_corrected_fee() public {
        vm.createSelectFork("rhc");
        address owner = ExecutorV4Morpho(payable(EXEC)).owner();

        RouteLeg[] memory legs = new RouteLeg[](2);
        legs[0] = RouteLeg({
            venue: 0,
            v3Pool: V3POOL,
            inTok: USDG,
            outTok: DED,
            zeroForOne: true, // 0x5fc5.. < 0xded8..: inTok is token0
            sqrtPriceLimitX96: 0, // contract defaults to min/max
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
            inTok: DED,
            outTok: USDG,
            zeroForOne: false,
            sqrtPriceLimitX96: 0,
            fee: 38962, // observed on-chain in 28/28 recent swaps (was 38000)
            tickSpacing: 380, // v4-overrides.csv
            hooks: address(0), // v4-overrides.csv
            hookData: "",
            pool: PM,
            poolKey: V4POOLID
        });

        vm.prank(owner);
        try ExecutorV4Morpho(payable(EXEC)).executeMorphoHybrid(
            USDG,
            154148419, // row-2 input (~$154)
            abi.encode(legs),
            0 // minProfit 0: we assert reachability, not profit
        ) {
            console.log("EXECUTED with profit (unexpected at this size, path proven)");
        } catch (bytes memory err) {
            bytes4 sel;
            assembly {
                sel := mload(add(err, 32))
            }
            console.log("revert selector:");
            console.logBytes4(sel);
            assertEq(
                sel,
                ExecutorV4Morpho.ProfitTooLow.selector,
                "route must reach settlement (ProfitTooLow), not revert earlier"
            );
        }
    }

    /// Key-variant matrix for pool 7159c4…: exactly one of these should get
    /// past the router (success or ProfitTooLow). Each case logs its revert
    /// selector; the matrix adjudicates fee-vs-tick without archive access.
    /// Cases: A catalog+override as-shipped, B observed-fee fix, C/D with
    /// heuristic spacing 60.
    function test_row2_key_matrix() public {
        vm.createSelectFork("rhc");
        address owner = ExecutorV4Morpho(payable(EXEC)).owner();
        uint24[4] memory fees = [uint24(38000), uint24(38962), uint24(38962), uint24(38000)];
        int24[4] memory ticks = [int24(380), int24(380), int24(60), int24(60)];
        bytes1[4] memory tags = [bytes1("A"), bytes1("B"), bytes1("C"), bytes1("D")];
        for (uint256 i = 0; i < 4; i++) {
            RouteLeg[] memory legs = new RouteLeg[](2);
            legs[0] = RouteLeg({
                venue: 0,
                v3Pool: V3POOL,
                inTok: USDG,
                outTok: DED,
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
                inTok: DED,
                outTok: USDG,
                zeroForOne: false,
                sqrtPriceLimitX96: 0,
                fee: fees[i],
                tickSpacing: ticks[i],
                hooks: address(0),
                hookData: "",
                pool: PM,
                poolKey: V4POOLID
            });
            vm.prank(owner);
            try ExecutorV4Morpho(payable(EXEC)).executeMorphoHybrid(
                USDG, 154148419, abi.encode(legs), 0
            ) {
                console.log("case reached settlement with profit");
                console.logBytes1(tags[i]);
            } catch (bytes memory err) {
                bytes4 sel;
                assembly {
                    sel := mload(add(err, 32))
                }
                console.log("case revert:");
                console.logBytes1(tags[i]);
                console.logBytes4(sel);
            }
        }
    }
}
