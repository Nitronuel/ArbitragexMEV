// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./ExecutorUUPS.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "forge-std/console.sol";
import "forge-std/Test.sol";

/// Fork test for the executor venue=2 leg (direct PM.swap, added 2026-09-16
/// to close the Fables router gap pinned in ForkFablesSettle).
///
/// The live proxy is NEVER touched: a fresh ExecutorUUPS is deployed behind
/// an ERC1967 proxy, initialized to this test, funded via deal().
///
/// Route (fully cyclic, mirrors the real arb shape):
///   USDG -[venue=2, Fables hook pool 0x486435a1…, fee 0x800000, ts 60]-> 0x39db
///   0x39db -[venue=0, V3 0x52e65B17… fee 100]-> USDG
///
/// PASS criterion (same discipline as ForkSep15Live): the run reverts with
/// ProfitTooLow from the FINAL settlement guard. That is only reachable if
/// (a) PM.unlock ran inside the executor, (b) the hook swap settled with
/// output > 0 (NoProfit would fire on leg 0 otherwise), (c) sync/settle/take
/// completed, and (d) the V3 leg settled. Any other revert = real defect.
/// A second test proves the fail-closed poolKey id guard; a third proves
/// the one-shot/PM-only callback guard.

/// forge-std's log_bytes4 lives on the console contract, not Test — declare
/// it so the catch blocks can print the raw selector on mismatch.
contract Console4 {
    event log_bytes4(bytes4);
}

contract ForkFablesDirectLeg is Test, Console4 {
    address constant PM = 0x8366a39CC670B4001A1121B8F6A443A643e40951;
    address constant WETH = 0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73;
    address constant USDG = 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168;
    address constant TKN = 0x39dBED3a2bd333467115dE45665cC57F813C4571; // 0x39db

    // Fables shared-hook pool (registry constants cross-pinned in
    // ForkFablesSettle: poolId 0x486435a1…, hook 0x08e52564…, ts 60,
    // currency0 = 0x39db, currency1 = USDG, dynamic-fee sentinel).
    bytes32 constant FABLES_PID = 0x486435a1f76cd58193f854c6e6213cd05fd58d637865d02065ff558b387fa6ea;
    address constant FABLES_HOOK = 0x08E52564Bad99E05a694b4809F397edcA417A080;
    uint24 constant FEE_DYNAMIC = 0x800000;

    // Verified true-V3 closing leg: USDG/WETH fee 100 (slot0() answers,
    // non-Algebra — see ForkFablesSettle notes).
    address constant V3_USDG_WETH = 0x52e65B17fB6E5BA00Ed806f37Afcd2DaA50271Ca;

    ExecutorUUPS exec;

    function _key0() internal pure returns (IPM.PoolKey memory) {
        // Registry order: currency0 = 0x39db (lower), currency1 = USDG.
        return IPM.PoolKey({
            currency0: TKN,
            currency1: USDG,
            fee: FEE_DYNAMIC,
            tickSpacing: 60,
            hooks: FABLES_HOOK
        });
    }

    function setUp() public {
        vm.createSelectFork("rhc");
        ExecutorUUPS impl = new ExecutorUUPS();
        ERC1967Proxy proxy = new ERC1967Proxy(
            address(impl), abi.encodeCall(ExecutorUUPS.initialize, (address(this)))
        );
        exec = ExecutorUUPS(payable(address(proxy)));
    }

    function _legs(bool goodId) internal view returns (bytes memory) {
        RouteLeg[] memory legs = new RouteLeg[](2);
        // Leg 0: USDG -> 0x39db through the Fables hook pool (venue=2).
        // sqrtPriceLimitX96 = 0: executor fills the price-rising max limit
        // (zeroForOne = currency0 == inTok = false here).
        legs[0] = RouteLeg({
            venue: 2,
            v3Pool: address(0),
            inTok: USDG,
            outTok: TKN,
            zeroForOne: false,
            sqrtPriceLimitX96: 0,
            fee: FEE_DYNAMIC,
            tickSpacing: 60,
            hooks: FABLES_HOOK,
            hookData: "",
            pool: address(0),
            poolKey: goodId ? FABLES_PID : bytes32(uint256(0xdead))
        });
        // Leg 1: 0x39db -> USDG via the verified V3 pool (venue=0).
        bool zfo = IUniswapV3Like(V3_USDG_WETH).token0() == TKN;
        legs[1] = RouteLeg({
            venue: 0,
            v3Pool: V3_USDG_WETH,
            inTok: TKN,
            outTok: USDG,
            zeroForOne: zfo,
            sqrtPriceLimitX96: 0,
            fee: 100,
            tickSpacing: 0,
            hooks: address(0),
            hookData: "",
            pool: address(0),
            poolKey: bytes32(0)
        });
        return abi.encode(legs);
    }

    /// The settlement-mechanics proof: ProfitTooLow from the FINAL guard is
    /// the designed success outcome for an unprofitable real-price cycle.
    /// Uses try/catch selector pinning (this repo's live fork convention):
    /// the route must unwind to ProfitTooLow (0xdfaaa478) — reachable only if
    /// unlock ran, the hook swap filled, sync/settle/take completed, and the
    /// V3 leg settled. Anything else = real defect.
    function test_direct_leg_settles_through_hook() public {
        uint256 amount = 100e6;
        deal(USDG, address(exec), amount + 10_000); // + hook-fee headroom
        try exec.executeHybrid(USDG, amount, _legs(true), 0) {
            revert("cycle executed at live prices - free money is impossible");
        } catch (bytes memory err) {
            bytes4 sel;
            if (err.length >= 4) {
                assembly {
                    sel := mload(add(err, 32))
                }
            }
            assertEq(sel, ExecutorUUPS.ProfitTooLow.selector, "unexpected revert (bytes printed in failure)");
            emit log_bytes4(sel);
        }
    }

    /// Fail-closed guard: a wrong poolKey id (builder bug / stale registry)
    /// reverts before any PM state is touched.
    function test_direct_leg_rejects_wrong_pool_id() public {
        uint256 amount = 100e6;
        deal(USDG, address(exec), amount + 10_000);
        try exec.executeHybrid(USDG, amount, _legs(false), 0) {
            revert("wrong poolKey was accepted");
        } catch (bytes memory err) {
            bytes4 sel;
            if (err.length >= 4) {
                assembly {
                    sel := mload(add(err, 32))
                }
            }
            assertEq(sel, ExecutorUUPS.InvalidCallback.selector, "unexpected revert (bytes printed in failure)");
            emit log_bytes4(sel);
        }
    }

    /// Callback guard: only the PM may call unlockCallback.
    function test_unlock_callback_only_pm() public {
        try exec.unlockCallback("") {
            revert("unlockCallback accepted a non-PM caller");
        } catch (bytes memory err) {
            bytes4 sel;
            if (err.length >= 4) {
                assembly {
                    sel := mload(add(err, 32))
                }
            }
            assertEq(sel, ExecutorUUPS.NotPM.selector, "unexpected revert (bytes printed in failure)");
            emit log_bytes4(sel);
        }
    }

    /// Sanity: the executor's keccak(abi.encode(PoolKey)) derivation must
    /// reproduce the registry poolId — this is the venue=2 whitelist.
    function test_key_derivation_matches_registry_id() public pure {
        assertEq(keccak256(abi.encode(_key0())), FABLES_PID, "PoolKey encoding drift");
    }
}

interface IUniswapV3Like {
    function token0() external view returns (address);
}
