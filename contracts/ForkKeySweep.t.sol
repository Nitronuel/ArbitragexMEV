// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/// Fork key-sweep for the 2026-09-14 BAD_ARGS hit list (4 pools with
/// stable overrides; read-only, no broadcasts):
///  - 7159c4… (USDG/DED, leg fee 38000, tick 380)
///  - e9e93b… (USDG/0x18e6, leg fee 30400, tick 100)
///  - e172fe… (0x8ff9/USDg leg fee 9000, tick 90)
///  - 2500e7… (0x5691/USDg leg fee 7000, tick 100)
///
/// Each probe is a single-element 0x4d819a2a V4 call mirroring production
/// (directional c0/c1, recipient 0x0, minOut 1, deadline 0).
/// Discriminating outcomes per probe:
/// - OK (or any non-BAD_ARGS revert) => the router FOUND the pool: key
///   triple works. Executability at probe size is not asserted.
/// - `BAD_ARGS` (Error(string), 0x08c379a0) => key still wrong.
contract ForkKeySweep is Test {
    address constant ROUTER = 0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc;
    address constant PM = 0x8366a39CC670B4001A1121B8F6A443A643e40951;

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

    function _probe(
        address c0,
        address c1,
        uint24 fee,
        int24 tick,
        uint256 amountIn
    ) internal returns (bool ok, bytes4 sel) {
        REL[] memory els = new REL[](1);
        els[0] = REL({
            venue: 2,
            c0: c0,
            c1: c1,
            pool: address(0),
            fee: fee,
            tickSpacing: tick,
            hooks: address(0),
            hookData: "",
            pm: PM,
            poolKey: bytes32(0)
        });
        deal(c0, address(this), amountIn);
        IERC20(c0).approve(ROUTER, amountIn);
        bool ok;
        bytes memory ret;
        (ok, ret) = ROUTER.call(
            abi.encodeWithSelector(
                bytes4(0x4d819a2a), els, address(0), amountIn, uint256(1), uint256(0)
            )
        );
        IERC20(c0).approve(ROUTER, 0);
        if (!ok && ret.length >= 4) {
            assembly {
                sel := mload(add(ret, 32))
            }
        }
    }

    function _sweep(
        string memory name,
        address c0,
        address c1,
        uint256 amountIn,
        uint24[] memory fees,
        int24[] memory ticks,
        int24 overrideTick
    ) internal {
        for (uint256 i = 0; i < fees.length; i++) {
            for (uint256 j = 0; j < ticks.length; j++) {
                (bool ok, bytes4 sel) = _probe(c0, c1, fees[i], ticks[j], amountIn);
                if (ok) {
                    console.log(string.concat(name, " KEY FOUND"));
                    console.logUint(fees[i]);
                    console.logInt(ticks[j]);
                } else if (sel != bytes4(0x08c379a0)) {
                    console.log(string.concat(name, " NON-BADARGS"));
                    console.logUint(fees[i]);
                    console.logInt(ticks[j]);
                    console.logBytes4(sel);
                }
            }
        }
        console.log(string.concat(name, " sweep done"));
        // Order hedge: same catalog-fee/override-tick probe with c0/c1
        // swapped. If THIS succeeds while directional fails, production
        // must sort currencies before encoding (currently directional).
        (bool okS, bytes4 selS) = _probe(c1, c0, fees[0], overrideTick, amountIn);
        console.log(string.concat(name, " swapped:"), okS ? "OK" : "REVERT");
        if (!okS) {
            console.logBytes4(selS);
        }
    }

    function test_key_sweep_badargs_pools() public {
        vm.createSelectFork(vm.envString("CHAINSTACK_RHC_HTTP_URL"));
        // Fee candidates: catalog leg fee, observed Swap fee (7159c4:
        // 38962 charged on 28/28 swaps per ForkRow2Pin), dynamic sentinel.
        uint24[] memory fees1 = new uint24[](3);
        fees1[0] = 38000;
        fees1[1] = 38962;
        fees1[2] = 0x800000;
        uint24[] memory fees2 = new uint24[](2);
        fees2[0] = 30400;
        fees2[1] = 0x800000;
        uint24[] memory fees3 = new uint24[](2);
        fees3[0] = 9000;
        fees3[1] = 0x800000;
        uint24[] memory fees4 = new uint24[](2);
        fees4[0] = 7000;
        fees4[1] = 0x800000;
        int24[] memory ticks = new int24[](9);
        ticks[0] = 380;
        ticks[1] = 100;
        ticks[2] = 90;
        ticks[3] = 1;
        ticks[4] = 8;
        ticks[5] = 10;
        ticks[6] = 60;
        ticks[7] = 200;
        ticks[8] = 2;
        address USDG = 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168;
        _sweep(
            "7159c4",
            0xded852De9fe9bA9b6f27f39e8e81CF851A5C79cc,
            USDG,
            1e12,
            fees1,
            ticks,
            380
        );
        _sweep(
            "e9e93b",
            USDG,
            0x18E674231A58c239Dc7DaeDcffE15Ec3A24cff5c,
            1e12,
            fees2,
            ticks,
            100
        );
        _sweep(
            "e172fe",
            0x8Ff92566f2e81BDd68EDfAa8cde73942A723796b,
            USDG,
            1e12,
            fees3,
            ticks,
            90
        );
        _sweep(
            "2500e7",
            0x56910D4409F3a0C78C64DD8D0545FF0705389870,
            USDG,
            1e12,
            fees4,
            ticks,
            100
        );
    }
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}
