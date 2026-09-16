// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./ExecutorV4Morpho.sol";
import "forge-std/Test.sol";
import "forge-std/console.sol";

/// Fork pin for the 2026-09-12 row (0x5fc5/0x18E6, net $0.88, block 61256526):
/// `executeMorphoHybrid` reverts router-bubbled `BAD_ARGS` at estimate while
/// WETH-anchored rows through the same builder pass validation.
///
/// Discriminating outcomes (minProfit = 0):
/// - Success OR `ProfitTooLow` => legs execute through real pools. PATH
///   PROVEN for this shape (profitability at this size is not asserted).
/// - `BAD_ARGS` => reproduced; the `-vvv` trace below shows which internal
///   frame (V3 leg? V4 leg? router validation?) rejects the args.
contract ForkRow3Pin is Test {
    address constant EXEC = 0x727f41B647e9F0958dd539b0dFff4fc46A90A950;
    address constant ANCHOR = 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168;
    address constant OTHER = 0x18E674231A58c239Dc7DaeDcffE15Ec3A24cff5c;
    address constant PM = 0x8366a39CC670B4001A1121B8F6A443A643e40951;
    address constant V3POOL = 0xd75A3f0cE28C54cCFdBf0A1c54d5297750bD97E6;
    bytes32 constant V4POOLID =
        0xe9e93bd1fa0f05fcce035e0f4b456f7f8079e8da9a3dceefb0cc89607dfdaa6a;

    function test_row61256526_hybrid_executes() public {        vm.createSelectFork("rhc");
        // Leg order mirrors the Rust builder output for the recorded row:
        // [0] V4 0x5fc5 -> 0x18E6 (fee 30400, tick 100, hooks zero),
        // [1] V3 0x18E6 -> 0x5fc5 (fee 10000, zeroForOne: 0x18E6 < 0x5fc5).
        RouteLeg[] memory legs = new RouteLeg[](2);
        legs[0] = RouteLeg({
            venue: 1,
            v3Pool: address(0),
            inTok: ANCHOR,
            outTok: OTHER,
            zeroForOne: false,
            sqrtPriceLimitX96: 0,
            fee: 30400,
            tickSpacing: 100,
            hooks: address(0),
            hookData: "",
            pool: PM,
            poolKey: V4POOLID
        });
        legs[1] = RouteLeg({
            venue: 0,
            v3Pool: V3POOL,
            inTok: OTHER,
            outTok: ANCHOR,
            zeroForOne: true,
            sqrtPriceLimitX96: 0,
            fee: 10000,
            tickSpacing: 0,
            hooks: address(0),
            hookData: "",
            pool: address(0),
            poolKey: bytes32(0)
        });
        // Morpho flash needs no funding; caller needs gas only.
        // Prank as the owner: the proxy's onlyOwner gate rejects anyone else
        // (first replay died on OwnableUnauthorizedAccount, not the route).
        vm.prank(0x3219E15A8d1e82368340dfB6697fE6a6B41d686D);
        (bool ok, bytes memory ret) = EXEC.call(
            abi.encodeWithSelector(
                ExecutorV4Morpho.executeMorphoHybrid.selector,
                ANCHOR,
                26431129,
                abi.encode(legs),
                uint256(0)
            )
        );
        console.log("hybrid replay ok:");
        console.log(ok);
        if (!ok) {
            console.log("ret len:");
            console.log(ret.length);
        }
    }

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

    /// Router-direct probe: same pool, canonical (sorted) c0/c1.
    /// If this passes validation (executes or ProfitTooLow-style revert)
    /// while the directional order reverts BAD_ARGS, the router requires
    /// canonical currency order and the fix belongs in the executors'
    /// RouterEl construction.
    function test_router_canonical_order() public {
        vm.createSelectFork("rhc");
        address ROUTER = 0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc;
        address PM = 0x8366a39CC670B4001A1121B8F6A443A643e40951;
        // Fund + approve: the router pulls input via transferFrom.
        deal(ANCHOR, address(this), 26431129);
        ANCHOR.call(
            abi.encodeWithSelector(
                bytes4(0x095ea7b3),
                ROUTER,
                26431129
            )
        );
        REL[] memory els = new REL[](1);
        els[0] = REL({
            venue: 2,
            c0: OTHER, // 0x18E6 < 0x5fc5: canonical order
            c1: ANCHOR,
            pool: address(0),
            fee: 30400,
            tickSpacing: 100,
            hooks: address(0),
            hookData: "",
            pm: PM,
            poolKey: V4POOLID
        });
        (bool ok, ) = ROUTER.call(
            abi.encodeWithSelector(
                bytes4(0x4d819a2a),
                els,
                address(0), // recipient 0x0: output returns to caller contract
                26431129,
                uint256(1),
                uint256(0)
            )
        );
        console.log("router canonical ok:");
        console.log(ok);
    }

    /// Mirror probe with DIRECTIONAL order (c0=inTok, c1=outTok as the
    /// executor builds it). A-directional BAD_ARGS + B-canonical pass
    /// isolates currency order as the discriminator.
    function test_router_directional_order() public {        vm.createSelectFork("rhc");
        address ROUTER = 0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc;
        address PM = 0x8366a39CC670B4001A1121B8F6A443A643e40951;
        deal(ANCHOR, address(this), 26431129);
        ANCHOR.call(
            abi.encodeWithSelector(
                bytes4(0x095ea7b3),
                ROUTER,
                26431129
            )
        );
        REL[] memory els = new REL[](1);
        els[0] = REL({
            venue: 2,
            c0: ANCHOR, // directional: inTok first (0x5fc5 > 0x18E6)
            c1: OTHER,
            pool: address(0),
            fee: 30400,
            tickSpacing: 100,
            hooks: address(0),
            hookData: "",
            pm: PM,
            poolKey: V4POOLID
        });
        (bool ok, ) = ROUTER.call(
            abi.encodeWithSelector(
                bytes4(0x4d819a2a),
                els,
                address(0),
                26431129,
                uint256(1),
                uint256(0)
            )
        );
        console.log("router directional ok:");
        console.log(ok);
    }

    /// Variant probe: pool=PM instead of pool=0x0 (all else identical to
    /// the canonical probe). Pass (or non-BAD_ARGS revert) here isolates
    /// the zero pool field as the discriminator.
    function test_router_pool_pm() public {
        vm.createSelectFork("rhc");
        address ROUTER = 0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc;
        address PM = 0x8366a39CC670B4001A1121B8F6A443A643e40951;
        deal(ANCHOR, address(this), 26431129);
        ANCHOR.call(
            abi.encodeWithSelector(
                bytes4(0x095ea7b3),
                ROUTER,
                26431129
            )
        );
        REL[] memory els = new REL[](1);
        els[0] = REL({
            venue: 2,
            c0: OTHER,
            c1: ANCHOR,
            pool: PM,
            fee: 30400,
            tickSpacing: 100,
            hooks: address(0),
            hookData: "",
            pm: PM,
            poolKey: V4POOLID
        });
        (bool ok, ) = ROUTER.call(
            abi.encodeWithSelector(
                bytes4(0x4d819a2a),
                els,
                address(0),
                26431129,
                uint256(1),
                uint256(0)
            )
        );
        console.log("router pool-pm ok:");
        console.log(ok);
    }

    /// Control probe: pool 00dd2df2 passes router validation live (rows
    /// reach ProfitTooLow at estimate). If this passes here while e9e93b
    /// fails in the identical harness, the discriminator is pool-specific
    /// (hook/dynamic vs static), not harness error.
    function test_router_control_hook_pool() public {
        vm.createSelectFork("rhc");
        address ROUTER = 0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc;
        address PM = 0x8366a39CC670B4001A1121B8F6A443A643e40951;
        address WETH = 0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73;
        address TKN = 0x56910D4409F3a0C78C64DD8D0545FF0705389870;
        deal(WETH, address(this), 42810753192095227);
        WETH.call(
            abi.encodeWithSelector(
                bytes4(0x095ea7b3),
                ROUTER,
                42810753192095227
            )
        );
        REL[] memory els = new REL[](1);
        els[0] = REL({
            venue: 2,
            c0: WETH,
            c1: TKN,
            pool: PM,
            fee: 10000,
            tickSpacing: 200,
            hooks: 0x2cD91bD228ff4c537031d6b8204782090c84c0cC,
            hookData: "",
            pm: PM,
            poolKey: 0x00dd2df2f17d431cf3a0938f06c9cf9abc5e9643b6cc466ca3f71f3af246edf3
        });
        (bool ok, ) = ROUTER.call(
            abi.encodeWithSelector(
                bytes4(0x4d819a2a),
                els,
                address(0),
                42810753192095227,
                uint256(1),
                uint256(0)
            )
        );
        console.log("router control ok:");
        console.log(ok);
    }

    /// Executor-level control: row 61047891 (00dd2df2 hybrid) reaches
    /// ProfitTooLow at estimate live, i.e. passes router validation.
    /// Expect success-or-ProfitTooLow here (NOT BAD_ARGS) — proving the
    /// harness can pass validation and isolating e9e93b as pool-specific.
    function test_executor_control_hook_pool() public {
        vm.createSelectFork("rhc");
        address WETH = 0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73;
        address TKN = 0x56910D4409F3a0C78C64DD8D0545FF0705389870;
        address V3POOL = 0xD29893fFac8b29eC4Db2cfE0CDB3FE1377c028Ff;
        RouteLeg[] memory legs = new RouteLeg[](2);
        legs[0] = RouteLeg({
            venue: 1,
            v3Pool: address(0),
            inTok: WETH,
            outTok: TKN,
            zeroForOne: false,
            sqrtPriceLimitX96: 0,
            fee: 10000,
            tickSpacing: 200,
            hooks: 0x2cD91bD228ff4c537031d6b8204782090c84c0cC,
            hookData: "",
            pool: 0x8366a39CC670B4001A1121B8F6A443A643e40951,
            poolKey: 0x00dd2df2f17d431cf3a0938f06c9cf9abc5e9643b6cc466ca3f71f3af246edf3
        });
        legs[1] = RouteLeg({
            venue: 0,
            v3Pool: V3POOL,
            inTok: TKN,
            outTok: WETH,
            zeroForOne: false,
            sqrtPriceLimitX96: 0,
            fee: 10000,
            tickSpacing: 0,
            hooks: address(0),
            hookData: "",
            pool: address(0),
            poolKey: bytes32(0)
        });
        vm.prank(0x3219E15A8d1e82368340dfB6697fE6a6B41d686D);
        (bool ok, bytes memory ret) = EXEC.call(
            abi.encodeWithSelector(
                ExecutorV4Morpho.executeMorphoHybrid.selector,
                WETH,
                42810753192095227,
                abi.encode(legs),
                uint256(0)
            )
        );
        console.log("executor control ok:");
        console.log(ok);
        if (!ok) {
            console.logBytes(ret);
        }
    }

    /// Discriminator probe: STANDARD tier (3000/60) ZERO-hook pool,
    /// recently evaluated live. Pass (or non-BAD_ARGS) => the router
    /// rejects nonstandard fee tiers; BAD_ARGS => it rejects zero-hook
    /// pools regardless of tier.
    function test_router_standard_zero_hook() public {
        vm.createSelectFork("rhc");
        address ROUTER = 0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc;
        address PM = 0x8366a39CC670B4001A1121B8F6A443A643e40951;
        address WETH = 0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73;
        address TKN = 0x4a6Eec8A30b49d289B9Fc865Fd374b4D61eab8fB;
        // WETH is a proxy: deal() misses its balance slot, so fund by
        // wrapping native ETH instead (deterministic on fork).
        vm.deal(address(this), 1 ether);
        WETH.call{value: 0.01 ether}(abi.encodeWithSelector(bytes4(0xd0e30db0)));
        (bool appr,) = WETH.call(
            abi.encodeWithSelector(
                bytes4(0x095ea7b3),
                ROUTER,
                3912716204350555
            )
        );
        require(appr, "approve failed");
        REL[] memory els = new REL[](1);
        els[0] = REL({
            venue: 2,
            c0: WETH,
            c1: TKN,
            pool: PM,
            fee: 3000,
            tickSpacing: 60,
            hooks: address(0),
            hookData: "",
            pm: PM,
            poolKey: 0x1f00bab0dfb60102287e2508b7d41a0a97a9dec2c9317bc9c81a4fb91a731be3
        });
        (bool ok, bytes memory ret) = ROUTER.call(
            abi.encodeWithSelector(
                bytes4(0x4d819a2a),
                els,
                address(0),
                3912716204350555,
                uint256(1),
                uint256(0)
            )
        );
        console.log("router std-zero-hook ok:");
        console.log(ok);
        if (!ok) {
            console.logBytes(ret);
        }
    }
}
