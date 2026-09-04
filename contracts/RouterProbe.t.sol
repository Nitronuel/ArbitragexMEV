/// Router viability probe: single-V4-element swap through 0x4d819a2a on fork.
/// Encodes per payload_builder docs (venue=2, input->output direction).
/// Run: forge test --fork-url https://rpc.mainnet.chain.robinhood.com --match-contract RouterProbe -vv
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "forge-std/Test.sol";

interface IERC20R {
    function approve(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

contract RouterProbe is Test {
    address constant ROUTER = 0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc;
    address constant PM = 0x8366a39CC670B4001A1121B8F6A443A643e40951;

    struct REl {
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

    function swapOne(
        address inTok,
        address outTok,
        uint24 fee,
        int24 ts,
        address hooks,
        uint256 amountIn
    ) internal returns (uint256 outBefore, uint256 outAfter, bool ok) {
        REl[] memory els = new REl[](1);
        els[0] = REl({
            venue: 2,
            c0: inTok,
            c1: outTok,
            pool: address(0),
            fee: fee,
            tickSpacing: ts,
            hooks: hooks,
            hookData: "",
            pm: PM,
            poolKey: bytes32(0)
        });
        bytes memory cd = abi.encodeWithSelector(
            bytes4(0x4d819a2a),
            els,
            address(0),
            amountIn,
            1,
            block.timestamp + 300
        );
        outBefore = outTok == address(0)
            ? address(this).balance
            : IERC20R(outTok).balanceOf(address(this));
        if (inTok == address(0)) {
            (ok,) = ROUTER.call{value: amountIn}(cd);
        } else {
            require(IERC20R(inTok).approve(ROUTER, amountIn), "approve");
            (ok,) = ROUTER.call(cd);
            require(IERC20R(inTok).approve(ROUTER, 0), "clear");
        }
        outAfter = outTok == address(0)
            ? address(this).balance
            : IERC20R(outTok).balanceOf(address(this));
    }

    // Exact replica of live tx 0xd21228 (native -> 0xb8bb, fee 0, tick 200,
    // hook 0xe5e7, recipient self, dust amount) to isolate caller/args issues.
    function test_router_live_replica() public {
        if (block.chainid != 4663) return;
        deal(address(this), 10 ether);
        (uint256 b, uint256 a, bool ok) = swapOne(
            address(0),
            0x0b8bbBE6C7439E938477f57e8a88598813125Adc,
            0,
            200,
            0xE5e702641Ea86F4ae6cC3cDaeD2B886f976Be044,
            20000000000000000
        );
        emit log_named_uint("replica out", a - b);
        assertTrue(ok, "router live replica failed");
    }

    // Live-pattern replica: ERC20 0x37df -> native, fee 0, tick 200,
    // hook 0xe5e7, deadline 0 (as in live tx 0x27ca25).
    function test_router_erc20_live_pattern() public {
        if (block.chainid != 4663) return;
        address t0 = 0x37DF8f590D93146116d1E77B2c6597932E1Cb335;
        deal(t0, address(this), 1e24);
        REl[] memory els = new REl[](1);
        els[0] = REl({
            venue: 2,
            c0: t0,
            c1: address(0),
            pool: address(0),
            fee: 0,
            tickSpacing: 200,
            hooks: 0xE5e702641Ea86F4ae6cC3cDaeD2B886f976Be044,
            hookData: "",
            pm: PM,
            poolKey: bytes32(0)
        });
        bytes memory cd = abi.encodeWithSelector(
            bytes4(0x4d819a2a),
            els,
            address(0),
            1e18,
            1,
            0
        );
        uint256 b = address(this).balance;
        require(IERC20R(t0).approve(ROUTER, 1e18), "approve");
        (bool ok,) = ROUTER.call(cd);
        require(IERC20R(t0).approve(ROUTER, 0), "clear");
        uint256 a = address(this).balance;
        emit log_named_uint("erc20-live-pattern out", a - b);
        assertTrue(ok, "router erc20 live pattern failed");
        assertGt(a, b, "no native output received");
    }

    // Dynamic-fee pool 33e020e8: 0x0dbc -> 0x39db, fee 0x800000, tick 8, hook 0x4e34.
    function test_router_dynamic_pool() public {
        if (block.chainid != 4663) return;
        address t0 = 0x0DBC9D99033B3615c27B3b70432524930F7c1e18;
        deal(t0, address(this), 1e18);
        emit log_named_uint("t0 bal", IERC20R(t0).balanceOf(address(this)));
        (uint256 b, uint256 a, bool ok) = swapOne(
            t0,
            0x39dBED3a2bd333467115dE45665cC57F813C4571,
            8388608,
            8,
            0x4e3468951D49f2EEa976eD0D6e75fFCb44a9a544,
            1e15
        );
        emit log_named_uint("dynamic out", a - b);
        assertTrue(ok, "router dynamic swap failed");
        assertGt(a, b, "no output received");
    }

    // Static pool f8073763: USDG -> 0xf0c4, fee 1000, tick 10, no hook.
    function test_router_static_pool() public {
        if (block.chainid != 4663) return;
        address usdg = 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168;
        deal(usdg, address(this), 1_000_000_000);
        (uint256 b, uint256 a, bool ok) = swapOne(
            usdg,
            0xF0C4BF4C582cb3836e98394b1d4e7B7281101bE8,
            1000,
            10,
            address(0),
            1_000_000
        );
        emit log_named_uint("static out", a - b);
        assertTrue(ok, "router static swap failed");
        assertGt(a, b, "no output received");
    }

    receive() external payable {}
}
