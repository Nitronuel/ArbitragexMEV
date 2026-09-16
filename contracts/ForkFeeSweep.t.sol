// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/// Fee-drift probe for e9e93bd1 (creation key proven by PoolId preimage:
/// USDG/0x18e6, fee 30400, tick 100, hooks 0 — yet the router rejects it,
/// while quoter-baseline shows the pool charging 30400/30401/30405 across
/// blocks => dynamic fee with slow drift). Sweeps fee ±100 around the
/// catalog value plus markers. A hit proves dynamic-fee and yields the
/// refresh rule; total miss means hooks/tick are the problem instead.
contract ForkFeeSweep is Test {
    address constant ROUTER = 0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc;
    address constant PM = 0x8366a39CC670B4001A1121B8F6A443A643e40951;
    address constant USDG = 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168;
    address constant TOK = 0x18E674231A58c239Dc7DaeDcffE15Ec3A24cff5c;

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

    function _probe(uint24 fee) internal returns (bool ok, bytes4 sel) {
        REL[] memory els = new REL[](1);
        els[0] = REL({
            venue: 2,
            c0: USDG,
            c1: TOK,
            pool: address(0),
            fee: fee,
            tickSpacing: 100,
            hooks: address(0),
            hookData: "",
            pm: PM,
            poolKey: bytes32(0)
        });
        uint256 amountIn = 1e15;
        deal(USDG, address(this), amountIn);
        IERC20(USDG).approve(ROUTER, amountIn);
        bytes memory ret;
        (ok, ret) = ROUTER.call(
            abi.encodeWithSelector(
                bytes4(0x4d819a2a), els, address(0), amountIn, uint256(1), uint256(0)
            )
        );
        IERC20(USDG).approve(ROUTER, 0);
        if (!ok && ret.length >= 4) {
            assembly {
                sel := mload(add(ret, 32))
            }
        }
    }

    function test_fee_drift_sweep() public {
        vm.createSelectFork(vm.envString("CHAINSTACK_RHC_HTTP_URL"));
        uint24[] memory marks = new uint24[](3);
        marks[0] = 0;
        marks[1] = 0x800000;
        marks[2] = 30400;
        for (uint256 i = 0; i < marks.length; i++) {
            (bool ok, bytes4 sel) = _probe(marks[i]);
            console.log("mark fee:");
            console.logUint(marks[i]);
            console.log(ok ? "OK" : "REVERT");
            if (!ok) console.logBytes4(sel);
        }
        for (uint24 fee = 30300; fee <= 30510; fee++) {
            (bool ok, bytes4 sel) = _probe(fee);
            if (ok) {
                console.log("DRIFT HIT fee:");
                console.logUint(fee);
            } else if (sel != bytes4(0x08c379a0)) {
                console.log("NON-BADARGS fee:");
                console.logUint(fee);
                console.logBytes4(sel);
            }
        }
        console.log("drift sweep done");
    }
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}
