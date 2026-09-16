// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";
import "forge-std/console.sol";

/// minOut-semantics probe. Live venue-2 legs succeed with minOut=0
/// (0xb98fd3…) or big minOut (0xf4a3c1…); our executor always sends
/// minOut=1. If minOut=1 is what the new impl rejects, EVERY V4-via-router
/// leg we build is dead on arrival regardless of key.
contract ForkMinOut is Test {
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

    function _call(
        address c0,
        address c1,
        uint24 fee,
        int24 tick,
        address hooks,
        uint256 amountIn,
        uint256 minOut
    ) internal returns (bool ok, bytes4 sel) {
        REL[] memory els = new REL[](1);
        els[0] = REL({
            venue: 2,
            c0: c0,
            c1: c1,
            pool: address(0),
            fee: fee,
            tickSpacing: tick,
            hooks: hooks,
            hookData: "",
            pm: PM,
            poolKey: bytes32(0)
        });
        deal(c0, address(this), amountIn);
        IERC20(c0).approve(ROUTER, amountIn);
        bytes memory ret;
        (ok, ret) = ROUTER.call(
            abi.encodeWithSelector(
                bytes4(0x4d819a2a), els, address(0), amountIn, minOut, uint256(0)
            )
        );
        IERC20(c0).approve(ROUTER, 0);
        if (!ok && ret.length >= 4) {
            assembly {
                sel := mload(add(ret, 32))
            }
        }
    }

    function test_minout_semantics() public {
        vm.createSelectFork(vm.envString("CHAINSTACK_RHC_HTTP_URL"));
        // Live-good leg B verbatim key, our minOut=1 vs live minOut=0.
        address c0 = 0x2BF8cE7d31F5856ACa4Bd8d4e3a99E336a0c1e18;
        address c1 = 0x1937caD42b17D43bB2b347ce16d5288887C46c33;
        uint256 amt = 1e15;
        (bool ok1,) = _call(c0, c1, 0x800000, 8, 0x4e3468951D49f2EEa976eD0D6e75fFCb44a9a544, amt, 1);
        console.log(ok1 ? "livekey-minOut1 OK" : "livekey-minOut1 REVERT");
        (bool ok0,) = _call(c0, c1, 0x800000, 8, 0x4e3468951D49f2EEa976eD0D6e75fFCb44a9a544, amt, 0);
        console.log(ok0 ? "livekey-minOut0 OK" : "livekey-minOut0 REVERT");
        // Certain key 7159c4, both minOuts.
        address USDG = 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168;
        address DED = 0xded852De9fe9bA9b6f27f39e8e81CF851A5C79cc;
        (bool ok3,) = _call(USDG, DED, 38000, 380, address(0), 1e18, 1);
        console.log(ok3 ? "certain-minOut1 OK" : "certain-minOut1 REVERT");
        (bool ok4,) = _call(USDG, DED, 38000, 380, address(0), 1e18, 0);
        console.log(ok4 ? "certain-minOut0 OK" : "certain-minOut0 REVERT");
    }
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}
