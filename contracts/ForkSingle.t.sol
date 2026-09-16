// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/// Focused probe: 7159c4 with the CERTAIN key (proven by PoolId preimage),
/// sorted order, live-mirror amounts. -vvvv trace shows the reverting frame.
contract ForkSingle is Test {
    address constant ROUTER = 0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc;
    address constant PM = 0x8366a39CC670B4001A1121B8F6A443A643e40951;
    address constant USDG = 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168;
    address constant DED = 0xded852De9fe9bA9b6f27f39e8e81CF851A5C79cc;

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

    function _call(
        address c0,
        address c1,
        uint24 fee,
        int24 tick,
        uint256 amountIn
    ) internal returns (bool ok, bytes memory ret) {
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
        (ok, ret) = ROUTER.call(
            abi.encodeWithSelector(
                bytes4(0x4d819a2a), els, address(0), amountIn, uint256(1), uint256(0)
            )
        );
        IERC20(c0).approve(ROUTER, 0);
    }

    function test_single_sorted_certain_key() public {
        vm.createSelectFork(vm.envString("CHAINSTACK_RHC_HTTP_URL"));
        (bool ok, bytes memory ret) = _call(USDG, DED, 38000, 380, 1e18);
        console.log(ok ? "SORTED OK" : "SORTED REVERT");
        console.logBytes(ret);
    }

    function _callFull(
        address c0,
        address c1,
        uint24 fee,
        int24 tick,
        uint256 amountIn,
        uint256 minOut,
        uint256 deadline
    ) internal returns (bool ok, bytes memory ret) {
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
        (ok, ret) = ROUTER.call(
            abi.encodeWithSelector(
                bytes4(0x4d819a2a), els, address(0), amountIn, minOut, deadline
            )
        );
        IERC20(c0).approve(ROUTER, 0);
    }

    function test_toplevel_matrix() public {
        vm.createSelectFork(vm.envString("CHAINSTACK_RHC_HTTP_URL"));
        (bool okC,) = _callFull(USDG, DED, 38000, 380, 1e18, 1e12, block.timestamp + 3600);
        console.log(okC ? "C minOut-big/future OK" : "C minOut-big/future REVERT");
        (bool okD,) = _callFull(USDG, DED, 38000, 380, 1e18, 1, block.timestamp + 3600);
        console.log(okD ? "D minOut-1/future OK" : "D minOut-1/future REVERT");
    }

    /// hooks≠0 gate probe: same certain key but with a live hook address.
    /// Any non-BAD_ARGS outcome (deeper trace, PM calls, different
    /// selector) proves the impl gates hookless venue-2 legs.
    function test_hooks_gate() public {
        vm.createSelectFork(vm.envString("CHAINSTACK_RHC_HTTP_URL"));
        REL[] memory els = new REL[](1);
        els[0] = REL({
            venue: 2,
            c0: USDG,
            c1: DED,
            pool: address(0),
            fee: 38000,
            tickSpacing: 380,
            hooks: 0x4e3468951D49f2EEa976eD0D6e75fFCb44a9a544,
            hookData: "",
            pm: PM,
            poolKey: bytes32(0)
        });
        uint256 amountIn = 1e18;
        deal(USDG, address(this), amountIn);
        IERC20(USDG).approve(ROUTER, amountIn);
        (bool ok, bytes memory ret) = ROUTER.call(
            abi.encodeWithSelector(
                bytes4(0x4d819a2a), els, address(0), amountIn, uint256(1), uint256(0)
            )
        );
        console.log(ok ? "HOOKS OK" : "HOOKS REVERT");
        console.logBytes(ret);
    }
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}
