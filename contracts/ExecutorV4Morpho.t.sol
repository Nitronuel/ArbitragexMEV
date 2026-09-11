// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./ExecutorV4Morpho.sol";
import "forge-std/Test.sol";
import "forge-std/console.sol";

/// Mock V3 Pool (positive amountSpecified = exact input). Calls back the V4
/// executor; output carries the profit and is actually delivered.
contract MockV3PoolV4 {
    address public immutable EXEC;

    error InvalidCallback();
    error NotExecutor();

    constructor(address _exec) { EXEC = _exec; }

    function swap(
        address payable recipient,
        bool zeroForOne,
        int256 amountSpecified,
        uint160 sqrtPriceLimitX96,
        bytes calldata data
    ) external returns (int256 amount0, int256 amount1) {
        if (msg.sender != EXEC) revert NotExecutor();
        require(amountSpecified > 0, "mock v3 needs positive exact input");
        (address c0, address c1,) = abi.decode(data, (address, address, uint24));
        uint256 outAmount = uint256(amountSpecified) + 1000;
        if (zeroForOne) {
            amount0 = amountSpecified;
            amount1 = -int256(outAmount);
            MockERC20V4(c1).mint(recipient, outAmount);
        } else {
            amount1 = amountSpecified;
            amount0 = -int256(outAmount);
            MockERC20V4(c0).mint(recipient, outAmount);
        }
        (bool ok, ) = recipient.call{gas: 50000}(
            abi.encodeWithSelector(ExecutorV4Morpho.uniswapV3SwapCallback.selector, amount0, amount1, data)
        );
        if (!ok) revert InvalidCallback();
    }

    receive() external payable {}
}

/// Minimal mock ERC20 with open mint (test funding only).
contract MockERC20V4 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) public {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external virtual returns (bool) {
        require(balanceOf[msg.sender] >= amount, "bal");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external virtual returns (bool) {
        require(balanceOf[from] >= amount, "bal");
        if (allowance[from][msg.sender] != type(uint256).max) {
            require(allowance[from][msg.sender] >= amount, "allow");
            allowance[from][msg.sender] -= amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

/// Mock wrapped native (etched at RHC_WNATIVE in route tests): 1:1
/// deposit/withdraw over the mock ledger.
contract MockWETHV4 is MockERC20V4 {
    function deposit() external payable {
        mint(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "short");
        balanceOf[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }

    receive() external payable {}
}

/// Mock router (etched over the real router address): single- or multi-
/// element 0x4d819a2a swaps. Mirrors proven live behavior: recipient must be
/// address(0), pulls exact amountIn per element, pays amountIn + 1000.
contract MockRouterV4 {
    error BadRecipient();
    error BadVenue();

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

    function swap(
        REl[] calldata els,
        address recipient,
        uint256 amountIn,
        uint256 minOut,
        uint256 deadline
    ) external payable returns (uint256 totalOut) {
        if (recipient != address(0)) revert BadRecipient();
        if (els.length == 0) revert BadVenue();
        if (deadline != 0) require(block.timestamp <= deadline, "expired");
        uint256 curIn = amountIn;
        uint256 valueLeft = msg.value;
        for (uint256 i = 0; i < els.length; i++) {
            REl calldata e = els[i];
            if (e.venue != 2) revert BadVenue();
            uint256 out;
            if (e.c0 == address(0)) {
                require(valueLeft >= curIn, "no value");
                valueLeft -= curIn;
                out = curIn + 1000;
            } else {
                require(
                    MockERC20V4(e.c0).transferFrom(msg.sender, address(this), curIn),
                    "pull failed"
                );
                out = curIn + 1000;
            }
            if (e.c1 == address(0)) {
                payable(msg.sender).transfer(out);
            } else {
                MockERC20V4(e.c1).mint(msg.sender, out);
            }
            curIn = out;
        }
        totalOut = curIn;
        require(totalOut >= minOut, "minOut");
    }

    receive() external payable {}
}

/// Mock Morpho Blue with real-Blue mechanics: fund the borrower, run the
/// callback, then pull the loan back via transferFrom (requires the
/// borrower's approval — exactly like the real singleton).
contract MockMorphoBlue {
    function flashLoan(address token, uint256 assets, bytes calldata data) external {
        require(MockERC20V4(token).transfer(msg.sender, assets), "fund failed");
        ExecutorV4Morpho(payable(msg.sender)).onMorphoFlashLoan(assets, data);
        require(
            MockERC20V4(token).transferFrom(msg.sender, address(this), assets),
            "pull failed"
        );
    }
}

/// Rogue lender variant: funds `assets` but reports `assets - 1` to the
/// callback (must trip FlashMismatch before any leg runs).
contract MockBlueMismatch {
    function flashLoan(address token, uint256 assets, bytes calldata data) external {
        require(MockERC20V4(token).transfer(msg.sender, assets), "fund failed");
        ExecutorV4Morpho(payable(msg.sender)).onMorphoFlashLoan(assets - 1, data);
        require(
            MockERC20V4(token).transferFrom(msg.sender, address(this), assets),
            "pull failed"
        );
    }
}
/// mode 0 = overcharge (demands specified + 100),
/// mode 1 = double callback (second must fail the one-shot whitelist).
/// Evil V3 pool: honest swap math, malicious callback.
/// mode 0 = overcharge (demands specified + 100),
contract MockEvilV3Pool {
    address public immutable EXEC;
    uint8 public immutable MODE;

    error NotExecutor();

    constructor(address _exec, uint8 _mode) { EXEC = _exec; MODE = _mode; }

    function swap(
        address payable recipient,
        bool zeroForOne,
        int256 amountSpecified,
        uint160 sqrtPriceLimitX96,
        bytes calldata data
    ) external returns (int256 amount0, int256 amount1) {
        if (msg.sender != EXEC) revert NotExecutor();
        require(amountSpecified > 0, "mock v3 needs positive exact input");
        (address c0, address c1,) = abi.decode(data, (address, address, uint24));
        uint256 outAmount = uint256(amountSpecified) + 1000;
        if (zeroForOne) {
            amount0 = amountSpecified + (MODE == 0 ? int256(100) : int256(0));
            amount1 = -int256(outAmount);
            MockERC20V4(c1).mint(recipient, outAmount);
        } else {
            amount1 = amountSpecified + (MODE == 0 ? int256(100) : int256(0));
            amount0 = -int256(outAmount);
            MockERC20V4(c0).mint(recipient, outAmount);
        }
        bytes memory cb = abi.encodeWithSelector(
            ExecutorV4Morpho.uniswapV3SwapCallback.selector, amount0, amount1, data
        );
        // Forward the callback outcome: a reverting callback (overcharge)
        // propagates as ok=false and the executor rejects it at settlement.
        // Mode 1 additionally proves the replayed callback fails.
        (bool ok, ) = recipient.call{gas: 60000}(cb);
        if (MODE == 1) {
            require(ok, "first callback must succeed");
            (bool ok2, ) = recipient.call{gas: 60000}(cb);
            require(!ok2, "double callback must fail");
        }
    }

    receive() external payable {}
}

/// Fee-on-transfer token: delivers 99%, burns 1%, deducts allowance in full.
contract MockFoTToken is MockERC20V4 {
    function transfer(address to, uint256 amount) external override returns (bool) {
        require(balanceOf[msg.sender] >= amount, "bal");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += (amount * 99) / 100;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external override returns (bool) {
        require(balanceOf[from] >= amount, "bal");
        if (allowance[from][msg.sender] != type(uint256).max) {
            require(allowance[from][msg.sender] >= amount, "allow");
            allowance[from][msg.sender] -= amount;
        }
        balanceOf[from] -= amount;
        balanceOf[to] += (amount * 99) / 100;
        return true;
    }
}

/// Reentrant token: transfer TO the owner attempts rescue() mid-callback
/// (must die on the reentrancy guard, unwinding the whole flash).
contract MockReentrantToken is MockERC20V4 {
    address public exec;
    address public ownerTarget;

    function arm(address _exec, address _owner) external {
        exec = _exec;
        ownerTarget = _owner;
    }

    function transfer(address to, uint256 amount) external override returns (bool) {
        if (to == ownerTarget && ownerTarget != address(0)) {
            ExecutorV4Morpho(payable(exec)).rescue(address(0), address(this), 0);
        }
        require(balanceOf[msg.sender] >= amount, "bal");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract ExecutorV4MorphoTest is Test {
    ExecutorV4Morpho public executor;
    MockERC20V4 public t0;
    MockERC20V4 public t1;
    MockV3PoolV4 public mockV3Pool;

    address constant ROUTER_ADDR = 0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc;
    address constant MORPHO_ADDR = 0x9D53d5E3bd5E8d4Cbfa6DB1ca238AEA02E651010;
    address constant WNATIVE = 0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73;
    MockWETHV4 constant WNATIVE_TOKEN = MockWETHV4(payable(0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73));

    function setUp() public {
        executor = new ExecutorV4Morpho();
        t0 = new MockERC20V4();
        t1 = new MockERC20V4();
        mockV3Pool = new MockV3PoolV4(address(executor));
        MockRouterV4 mockRouter = new MockRouterV4();
        vm.etch(ROUTER_ADDR, address(mockRouter).code);
        deal(ROUTER_ADDR, 100 ether);
        MockMorphoBlue mockBlue = new MockMorphoBlue();
        vm.etch(MORPHO_ADDR, address(mockBlue).code);
    }

    function _v4leg(address inTok, address outTok) internal pure returns (RouteLeg memory) {
        return RouteLeg({
            venue: 1,
            v3Pool: address(0),
            inTok: inTok,
            outTok: outTok,
            zeroForOne: false,
            sqrtPriceLimitX96: 0,
            fee: 0,
            tickSpacing: 200,
            hooks: address(0),
            hookData: "",
            pool: address(0),
            poolKey: bytes32(0)
        });
    }

    function _cycle(address a, address b) internal pure returns (bytes memory) {
        RouteLeg[] memory legs = new RouteLeg[](2);
        legs[0] = _v4leg(a, b);
        legs[1] = _v4leg(b, a);
        return abi.encode(legs);
    }

    function test_constructor_sets_owner_and_morpho() public {
        assertEq(executor.owner(), address(this));
        assertEq(executor.MORPHO(), MORPHO_ADDR);
    }

    function test_onlyOwner_reverts() public {
        vm.prank(address(0x1234));
        vm.expectRevert(ExecutorV4Morpho.NotOwner.selector);
        executor.executeMorphoFlash(address(t0), 1 ether, "", 0);
    }

    function test_callback_rejects_non_morpho() public {
        bytes memory data = abi.encode(address(t0), uint256(1e18), hex"00", uint256(0), false);
        vm.prank(address(0x1234));
        vm.expectRevert(ExecutorV4Morpho.NotMorpho.selector);
        executor.onMorphoFlashLoan(1e18, data);
    }

    function test_callback_rejects_stale_flag() public {
        // Even Blue itself cannot run the callback outside a borrow: with no
        // borrow in progress (locked == 1) the reentrancy guard fires first.
        bytes memory data = abi.encode(address(t0), uint256(1e18), hex"00", uint256(0), false);
        vm.prank(MORPHO_ADDR);
        vm.expectRevert(ExecutorV4Morpho.Reentrancy.selector);
        executor.onMorphoFlashLoan(1e18, data);
    }

    function test_native_entry_reverts() public {
        vm.expectRevert(ExecutorV4Morpho.FlashUnsupported.selector);
        executor.executeMorphoFlash(address(0), 1 ether, "", 0);
    }

    function test_routeTooShort_reverts_before_blue() public {
        MockERC20V4(address(t0)).mint(MORPHO_ADDR, 10e18);
        vm.expectRevert(ExecutorV4Morpho.RouteTooShort.selector);
        executor.executeMorphoFlash(address(t0), 1e18, "", 0);
    }

    function test_morpho_twoLeg_cycle_repays_and_pays_owner() public {
        MockERC20V4(address(t0)).mint(MORPHO_ADDR, 10e18);
        // Executor starts empty: pure flash, no float.
        assertEq(t0.balanceOf(address(executor)), 0);
        executor.executeMorphoFlash(address(t0), 1e18, _cycle(address(t0), address(t1)), 0);
        // +1000 per mock router leg to the owner; Blue made whole; no residue.
        assertEq(t0.balanceOf(address(this)), 2000);
        assertEq(t0.balanceOf(address(executor)), 0);
        assertEq(t0.balanceOf(MORPHO_ADDR), 10e18);
    }

    function test_morpho_enforces_minProfit_and_keeps_blue_whole() public {
        MockERC20V4(address(t0)).mint(MORPHO_ADDR, 10e18);
        vm.expectRevert(ExecutorV4Morpho.ProfitTooLow.selector);
        executor.executeMorphoFlash(address(t0), 1e18, _cycle(address(t0), address(t1)), 2001);
        // Revert unwinds Blue's funding: lender whole, executor empty.
        assertEq(t0.balanceOf(MORPHO_ADDR), 10e18);
        assertEq(t0.balanceOf(address(executor)), 0);
    }

    function test_morpho_hybrid_with_v3_leg() public {
        (address a, address b) = address(t0) < address(t1)
            ? (address(t0), address(t1))
            : (address(t1), address(t0));
        RouteLeg[] memory legs = new RouteLeg[](2);
        legs[0] = RouteLeg({
            venue: 0,
            v3Pool: address(mockV3Pool),
            inTok: a,
            outTok: b,
            zeroForOne: true,
            sqrtPriceLimitX96: 0,
            fee: 3000,
            tickSpacing: 0,
            hooks: address(0),
            hookData: "",
            pool: address(0),
            poolKey: bytes32(0)
        });
        legs[1] = _v4leg(b, a);
        // Route starts at a: flash the leg-0 input token and mint Blue
        // inventory in it.
        MockERC20V4(a).mint(MORPHO_ADDR, 10e18);
        executor.executeMorphoHybrid(a, 1e18, abi.encode(legs), 0);
        assertEq(MockERC20V4(a).balanceOf(address(this)), 2000);
        assertEq(MockERC20V4(a).balanceOf(MORPHO_ADDR), 10e18);
    }

    function test_morpho_wrapped_anchor_native_legs_wrap_back() public {
        // WNATIVE-anchored mixed route: exact WNATIVE entry (alias entry is
        // rejected), V4 legs settle natively through the 0x0 sentinel, and the
        // terminal native output wraps back to WNATIVE for Blue's pull-back.
        MockWETHV4 mockWeth = new MockWETHV4();
        vm.etch(WNATIVE, address(mockWeth).code);
        deal(WNATIVE, 100 ether); // wrapper backing
        WNATIVE_TOKEN.mint(MORPHO_ADDR, 10e18); // Blue inventory
        RouteLeg[] memory legs = new RouteLeg[](2);
        legs[0] = _v4leg(WNATIVE, address(t0));
        legs[1] = _v4leg(address(t0), address(0));
        executor.executeMorphoFlash(WNATIVE, 1e18, abi.encode(legs), 0);
        // +1000 per leg, paid in WNATIVE; Blue whole; no residue.
        assertEq(WNATIVE_TOKEN.balanceOf(address(this)), 2000);
        assertEq(WNATIVE_TOKEN.balanceOf(MORPHO_ADDR), 10e18);
        assertEq(WNATIVE_TOKEN.balanceOf(address(executor)), 0);
    }

    function test_morpho_alias_entry_unwraps_and_executes() public {
        // Sentinel-form entry under a WNATIVE flash: leg-0 unwraps the flash
        // to native, the router legs run on value, terminal wraps back.
        MockWETHV4 mockWeth = new MockWETHV4();
        vm.etch(WNATIVE, address(mockWeth).code);
        deal(WNATIVE, 100 ether);
        WNATIVE_TOKEN.mint(MORPHO_ADDR, 10e18);
        RouteLeg[] memory legs = new RouteLeg[](2);
        legs[0] = _v4leg(address(0), address(t0));
        legs[1] = _v4leg(address(t0), address(0));
        executor.executeMorphoFlash(WNATIVE, 1e18, abi.encode(legs), 0);
        // +1000 per leg, settled in WNATIVE; Blue whole; no residue.
        assertEq(WNATIVE_TOKEN.balanceOf(address(this)), 2000);
        assertEq(WNATIVE_TOKEN.balanceOf(MORPHO_ADDR), 10e18);
        assertEq(WNATIVE_TOKEN.balanceOf(address(executor)), 0);
    }

    function test_float_fallback_intact() public {
        // V3 executor behavior preserved: seeded float, router cycle, profit.
        t0.mint(address(executor), 1e18);
        executor.executeHybrid(address(t0), 1e18, _cycle(address(t0), address(t1)), 0);
        assertEq(t0.balanceOf(address(this)), 2000);
        assertEq(t0.balanceOf(address(executor)), 1e18);
    }

    function test_float_short_reverts_fast() public {
        vm.expectRevert(ExecutorV4Morpho.ShortBalance.selector);
        executor.executeHybrid(address(t0), 1e18, _cycle(address(t0), address(t1)), 0);
    }

    function test_guards_reject_malformed_routes() public {
        // Blue must hold the flash token or its funding transfer (before any
        // callback) reverts with the mock's balance check.
        MockERC20V4(address(t0)).mint(MORPHO_ADDR, 10e18);
        RouteLeg[] memory empty = new RouteLeg[](0);
        vm.expectRevert(ExecutorV4Morpho.RouteEmpty.selector);
        executor.executeMorphoHybrid(address(t0), 1e18, abi.encode(empty), 0);
        RouteLeg[] memory broken = new RouteLeg[](2);
        broken[0] = _v4leg(address(t0), address(t1));
        broken[1] = _v4leg(address(t0), address(t1));
        MockERC20V4(address(t0)).mint(MORPHO_ADDR, 10e18);
        vm.expectRevert(ExecutorV4Morpho.NotCyclic.selector);
        executor.executeMorphoHybrid(address(t0), 1e18, abi.encode(broken), 0);
    }

    function test_rescue_only_owner() public {
        vm.prank(address(0x1234));
        vm.expectRevert(ExecutorV4Morpho.NotOwner.selector);
        executor.rescue(address(0), address(0x1234), 1);
    }

    function test_float_guards_reject_bad_lengths() public {
        // Length bounds now live in _runLegs: all four entries share them.
        vm.expectRevert(ExecutorV4Morpho.RouteTooLong.selector);
        executor.executeFlash(address(t0), 1e18, new bytes(8193), 0);
        vm.expectRevert(ExecutorV4Morpho.RouteTooShort.selector);
        executor.executeFlash(address(t0), 1e18, new bytes(31), 0);
        // Morpho path validates inside the callback (after funding), so Blue
        // must hold the token to reach the length check.
        MockERC20V4(address(t0)).mint(MORPHO_ADDR, 10e18);
        vm.expectRevert(ExecutorV4Morpho.RouteTooShort.selector);
        executor.executeMorphoHybrid(address(t0), 1e18, new bytes(31), 0);
    }

    function test_v3pool_zero_reverts_fast() public {
        RouteLeg[] memory legs = new RouteLeg[](2);
        legs[0] = RouteLeg({
            venue: 0, v3Pool: address(0), inTok: address(t0), outTok: address(t1),
            zeroForOne: true, sqrtPriceLimitX96: 0, fee: 3000,
            tickSpacing: 0, hooks: address(0), hookData: "",
            pool: address(0), poolKey: bytes32(0)
        });
        legs[1] = _v4leg(address(t1), address(t0));
        vm.expectRevert(ExecutorV4Morpho.BadVenue.selector);
        executor.executeHybrid(address(t0), 1e18, abi.encode(legs), 0);
    }

    function test_evil_pool_overcharge_reverts_intact() public {
        (address a, address b) = address(t0) < address(t1)
            ? (address(t0), address(t1))
            : (address(t1), address(t0));
        MockEvilV3Pool evil = new MockEvilV3Pool(address(executor), 0);
        RouteLeg[] memory legs = new RouteLeg[](2);
        legs[0] = RouteLeg({
            venue: 0, v3Pool: address(evil), inTok: a, outTok: b,
            zeroForOne: true, sqrtPriceLimitX96: 0, fee: 3000,
            tickSpacing: 0, hooks: address(0), hookData: "",
            pool: address(0), poolKey: bytes32(0)
        });
        legs[1] = _v4leg(b, a);
        // Overfund the float so the overcharge is payable — the callback
        // must still refuse it BEFORE paying.
        MockERC20V4(a).mint(address(executor), 1e18 + 1000);
        vm.expectRevert(ExecutorV4Morpho.InvalidCallback.selector);
        executor.executeHybrid(a, 1e18, abi.encode(legs), 0);
        assertEq(MockERC20V4(a).balanceOf(address(executor)), 1e18 + 1000);
    }

    function test_evil_pool_double_callback_contained() public {
        // The one-shot whitelist contains the replay AND the honest flow
        // still settles: pool paid exactly once, profit delivers.
        (address a, address b) = address(t0) < address(t1)
            ? (address(t0), address(t1))
            : (address(t1), address(t0));
        MockEvilV3Pool evil = new MockEvilV3Pool(address(executor), 1);
        RouteLeg[] memory legs = new RouteLeg[](2);
        legs[0] = RouteLeg({
            venue: 0, v3Pool: address(evil), inTok: a, outTok: b,
            zeroForOne: true, sqrtPriceLimitX96: 0, fee: 3000,
            tickSpacing: 0, hooks: address(0), hookData: "",
            pool: address(0), poolKey: bytes32(0)
        });
        legs[1] = _v4leg(b, a);
        MockERC20V4(a).mint(address(executor), 1e18);
        executor.executeHybrid(a, 1e18, abi.encode(legs), 0);
        assertEq(MockERC20V4(a).balanceOf(address(this)), 2000);
        assertEq(MockERC20V4(a).balanceOf(address(evil)), 1e18);
    }

    function test_v3_callback_without_pool_reverts() public {
        bytes memory data = abi.encode(address(t0), address(t1), uint24(3000));
        vm.expectRevert(ExecutorV4Morpho.InvalidCallback.selector);
        executor.uniswapV3SwapCallback(int256(1e18), -int256(1e18), data);
    }

    function test_zeroForOne_mismatch_reverts() public {
        // zeroForOne=true demands token0, but the route funds token1: the
        // callback sees the wrong token and refuses before paying.
        (address a, address b) = address(t0) < address(t1)
            ? (address(t0), address(t1))
            : (address(t1), address(t0));
        RouteLeg[] memory legs = new RouteLeg[](2);
        legs[0] = RouteLeg({
            venue: 0, v3Pool: address(mockV3Pool), inTok: b, outTok: a,
            zeroForOne: true, sqrtPriceLimitX96: 0, fee: 3000,
            tickSpacing: 0, hooks: address(0), hookData: "",
            pool: address(0), poolKey: bytes32(0)
        });
        legs[1] = _v4leg(a, b);
        MockERC20V4(b).mint(address(executor), 1e18);
        vm.expectRevert(ExecutorV4Morpho.InvalidCallback.selector);
        executor.executeHybrid(b, 1e18, abi.encode(legs), 0);
        assertEq(MockERC20V4(b).balanceOf(address(executor)), 1e18);
    }

    function test_morpho_fot_revert_keeps_blue_whole() public {
        // Fee-on-transfer anchor: Blue's funding transfer delivers 99%, so
        // leg-0 funding fails fast and the whole flash unwinds.
        MockFoTToken fot = new MockFoTToken();
        fot.mint(MORPHO_ADDR, 10e18);
        RouteLeg[] memory legs = new RouteLeg[](2);
        legs[0] = _v4leg(address(fot), address(t1));
        legs[1] = _v4leg(address(t1), address(fot));
        vm.expectRevert(ExecutorV4Morpho.ShortBalance.selector);
        executor.executeMorphoFlash(address(fot), 1e18, abi.encode(legs), 0);
        assertEq(fot.balanceOf(MORPHO_ADDR), 10e18);
        assertEq(fot.balanceOf(address(executor)), 0);
    }

    function test_reentrant_profit_token_reverts_blue_whole() public {
        // Profit payout triggers rescue() mid-callback: owner-auth stops it
        // (onlyOwner fires before any state moves) and the flash unwinds.
        MockReentrantToken ret = new MockReentrantToken();
        ret.arm(address(executor), address(this));
        ret.mint(MORPHO_ADDR, 10e18);
        RouteLeg[] memory legs = new RouteLeg[](2);
        legs[0] = _v4leg(address(ret), address(t1));
        legs[1] = _v4leg(address(t1), address(ret));
        vm.expectRevert(ExecutorV4Morpho.NotOwner.selector);
        executor.executeMorphoFlash(address(ret), 1e18, abi.encode(legs), 0);
        assertEq(ret.balanceOf(MORPHO_ADDR), 10e18);
        assertEq(ret.balanceOf(address(executor)), 0);
    }

    function test_amount_zero_reverts() public {
        vm.expectRevert(ExecutorV4Morpho.NoProfit.selector);
        executor.executeMorphoFlash(address(t0), 0, _cycle(address(t0), address(t1)), 0);
        t0.mint(address(executor), 1e18);
        vm.expectRevert(ExecutorV4Morpho.NoProfit.selector);
        executor.executeFlash(address(t0), 0, _cycle(address(t0), address(t1)), 0);
    }

    function test_assets_mismatch_reverts() public {
        // Rogue lender passes assets != encoded amount: caught before legs.
        MockBlueMismatch rogue = new MockBlueMismatch();
        vm.etch(MORPHO_ADDR, address(rogue).code);
        MockERC20V4(address(t0)).mint(MORPHO_ADDR, 10e18);
        vm.expectRevert(ExecutorV4Morpho.FlashMismatch.selector);
        executor.executeMorphoFlash(address(t0), 1e18, _cycle(address(t0), address(t1)), 0);
        assertEq(t0.balanceOf(MORPHO_ADDR), 10e18);
    }

    /// Cross-pinned with submit.rs `morpho_entry_selectors` (values via
    /// `cast sig` from the canonical signatures).
    function test_entry_selectors_match_rust_submitter() public pure {
        assertEq(
            uint32(ExecutorV4Morpho.executeMorphoFlash.selector),
            uint32(0x5fea06fd)
        );
        assertEq(
            uint32(ExecutorV4Morpho.executeMorphoHybrid.selector),
            uint32(0x68b9f938)
        );
    }

    /// Cross-language regression: bytes produced by the Rust submitter
    /// (`EntryPoint::MorphoHybrid.encode`, MORPHOCALLDATA_HEX from
    /// `cargo test -p shadow-bot --bin shadow-bot morpho_cross_pin_emit_calldata
    /// -- --nocapture`) must execute end-to-end on-chain.
    function test_rust_morpho_calldata_executes() public {
        address tokA = address(0x1111111111111111111111111111111111111111);
        address tokB = address(0x2222222222222222222222222222222222222222);
        MockERC20V4 ta = new MockERC20V4();
        MockERC20V4 tb = new MockERC20V4();
        vm.etch(tokA, address(ta).code);
        vm.etch(tokB, address(tb).code);
        MockERC20V4(tokA).mint(MORPHO_ADDR, 10e18); // Blue inventory
        bytes memory raw = hex"68b9f93800000000000000000000000011111111111111111111111111111111111111110000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000003c000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001e0000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000001111111111111111111111111111111111111111000000000000000000000000222222222222222222222222222222222222222200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000002222222222222222222222222222222222222222000000000000000000000000111111111111111111111111111111111111111100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000180000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        (bool ok, ) = address(executor).call(raw);
        assertTrue(ok, "rust calldata must execute");
        assertEq(MockERC20V4(tokA).balanceOf(address(this)), 2000);
        assertEq(MockERC20V4(tokA).balanceOf(MORPHO_ADDR), 10e18);
        assertEq(MockERC20V4(tokA).balanceOf(address(executor)), 0);
    }

    receive() external payable {}
}

/// Fork mechanics: ExecutorV4Morpho against REAL Blue + REAL router + REAL
/// pools on RHC. A same-pool roundtrip cannot profit (swap fees both ways),
/// so success = dying at the profit gate fully executed (Blue repaid
/// atomically). A dry token (Blue holds nothing) must revert at funding.
/// Run: forge test --fork-url http://127.0.0.1:8545 --match-contract ExecutorV4MorphoBlueForkTest -vv
/// (anvil fork of https://rpc.mainnet.chain.robinhood.com, chain 4663).
contract ExecutorV4MorphoBlueForkTest is Test {
    ExecutorV4Morpho public executor;

    address constant USDG = 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168;
    address constant DRY = 0x0b8bbBE6C7439E938477f57e8a88598813125Adc;

    function setUp() public {
        executor = new ExecutorV4Morpho();
    }

    function _v4leg(address inTok, address outTok, uint24 fee, int24 tick) internal pure returns (RouteLeg memory) {
        return RouteLeg({
            venue: 1,
            v3Pool: address(0),
            inTok: inTok,
            outTok: outTok,
            zeroForOne: false,
            sqrtPriceLimitX96: 0,
            fee: fee,
            tickSpacing: tick,
            hooks: address(0),
            hookData: "",
            pool: address(0),
            poolKey: bytes32(0)
        });
    }

    function test_blue_flash_roundtrip_reaches_profit_check() public {
        if (block.chainid != 4663) return; // requires the RHC fork
        // Live-proven dynamic pool (native<->0xccf1, sentinel fee, tick 8,
        // hooks 0x4e34 — byte-exact live tx replays on this fork). WNATIVE
        // flash unwraps to native for leg-0; same-pool roundtrip cannot
        // profit (hook + dynamic fees both ways): success = dying at the
        // profit gate, fully executed (Blue funded, router ran both legs,
        // Blue repaid atomically).
        address tok = 0xCcF14ec1f58B04baA52cE0C562899c26dB7d1E18;
        address hooks = 0x4e3468951D49f2EEa976eD0D6e75fFCb44a9a544;
        RouteLeg[] memory legs = new RouteLeg[](2);
        legs[0] = RouteLeg({
            venue: 1, v3Pool: address(0), inTok: address(0), outTok: tok,
            zeroForOne: false, sqrtPriceLimitX96: 0, fee: 8388608,
            tickSpacing: 8, hooks: hooks, hookData: "",
            pool: address(0), poolKey: bytes32(0)
        });
        legs[1] = RouteLeg({
            venue: 1, v3Pool: address(0), inTok: tok, outTok: address(0),
            zeroForOne: false, sqrtPriceLimitX96: 0, fee: 8388608,
            tickSpacing: 8, hooks: hooks, hookData: "",
            pool: address(0), poolKey: bytes32(0)
        });
        vm.expectRevert(ExecutorV4Morpho.ProfitTooLow.selector);
        executor.executeMorphoFlash(
            0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73, 0.5 ether, abi.encode(legs), 0
        );
    }

    function test_blue_dry_token_reverts_at_funding() public {
        if (block.chainid != 4663) return; // requires the RHC fork
        // DRY verified EMPTY on Blue (verify-blue): the flash cannot fund.
        RouteLeg[] memory legs = new RouteLeg[](2);
        legs[0] = _v4leg(DRY, USDG, 4500, 45);
        legs[1] = _v4leg(USDG, DRY, 4500, 45);
        vm.expectRevert(); // Blue's transfer fails — never reaches the legs
        executor.executeMorphoHybrid(DRY, 1e12, abi.encode(legs), 0);
    }
    /// Offline pool-key solver: finds which uint24 fee reproduces the catalog
    /// poolId for (currency0, currency1, tickSpacing, hooks). The CSV fee
    /// column is untrusted (known data-quality finding) — the router resolves
    /// pools by key, so a wrong fee fails as BAD_ARGS.
    function test_solve_pool_fee() public pure {
        address c0 = 0x32aC8C1D7672667D5EbdEa22935F7B06fC8D496f;
        address c1 = 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168;
        bytes32 want = 0x15bdcd39d0a5c3a8b74a607eebcf66a40f75dcce4673a003a38160c9fcba15f8;
        uint24[9] memory cands = [uint24(100), uint24(500), uint24(2500), uint24(3000), uint24(4500), uint24(10000), uint24(30000), uint24(50000), uint24(100000)];
        bool found;
        for (uint256 i = 0; i < cands.length; i++) {
            bytes32 got = keccak256(abi.encode(c0, c1, cands[i], int24(45), address(0)));
            if (got == want) {
                console.log("MATCH fee:", uint256(cands[i]));
                found = true;
            }
        }
        assertTrue(found, "no candidate fee reproduces the catalog poolId");
    }
}

/// Fork debugger: calls the REAL router directly (no executor) with the
/// catalog tuple to isolate BAD_ARGS. Prints the outcome for diagnosis.
contract RouterDebugForkTest is Test {
    address constant ROUTER = 0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc;
    address constant PM = 0x8366a39CC670B4001A1121B8F6A443A643e40951;
    address constant USDG = 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168;

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

    function test_direct_router_single_leg() public {
        if (block.chainid != 4663) return; // requires the RHC fork
        // Baseline: byte-exact live tx 0x104ce1e5 (proven 2026-08-28) replayed
        // with deal()'d native. Must execute — proves the fork + router are
        // live before any tuple debugging.
        deal(address(this), 1 ether);
        string memory liveHex = vm.readFile("crates/simulation/tests/fixtures/router_tx1.hex");
        bytes memory ascii = bytes(liveHex);
        // Strip a single trailing newline if present.
        if (ascii.length > 0 && ascii[ascii.length - 1] == 0x0a) {
            assembly {
                mstore(ascii, sub(mload(ascii), 1))
            }
        }
        bytes memory cd = vm.parseBytes(string(ascii));
        // Refresh the stale deadline: decode the proven args, re-stamp.
        bytes memory args = new bytes(cd.length - 4);
        for (uint256 i = 0; i < args.length; i++) {
            args[i] = cd[i + 4];
        }
        (REl[] memory els, address recipient, uint256 amountIn, uint256 minOut,) =
            abi.decode(args, (REl[], address, uint256, uint256, uint256));
        cd = abi.encodeWithSelector(
            bytes4(0x4d819a2a), els, recipient, amountIn, minOut, block.timestamp + 3600
        );
        (bool ok, bytes memory ret) = ROUTER.call{value: 0.02 ether}(cd);
        console.log("live-tx replay ok:", ok);
        if (!ok) console.logBytes(ret);
        assertTrue(ok, "proven live tx must replay on the fork");
    }

}
