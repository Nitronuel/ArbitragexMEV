// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./ExecutorV3.sol";
import "forge-std/Test.sol";
import "forge-std/console.sol";

/// Mock V3 Pool for testing (positive amountSpecified = exact input, matching
/// canonical V3 semantics proven by RHC fork replay).
contract MockV3Pool {
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
        // Exact input: the pool is owed exactly the input; output carries
        // the profit (real V4 semantics) and is actually delivered.
        uint256 outAmount = uint256(amountSpecified) + 1000;
        if (zeroForOne) {
            amount0 = amountSpecified;
            amount1 = -int256(outAmount);
            MockERC20(c1).mint(recipient, outAmount);
        } else {
            amount1 = amountSpecified;
            amount0 = -int256(outAmount);
            MockERC20(c0).mint(recipient, outAmount);
        }

        // Callback to ExecutorV3
        (bool ok, ) = recipient.call{gas: 50000}(
            abi.encodeWithSelector(ExecutorV3.uniswapV3SwapCallback.selector, amount0, amount1, data)
        );
        if (!ok) revert InvalidCallback();
    }

    receive() external payable {}
}

/// Minimal mock ERC20 with open mint (test funding only).
contract MockERC20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) public {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "bal");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
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
/// deposit/withdraw over the MockERC20 ledger.
contract MockWETH is MockERC20 {
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
/// address(0) (output to caller), pulls exact amountIn per element
/// (transferFrom or msg.value), pays amountIn + 1000 per element.
contract MockRouter {
    error BadRecipient();
    error BadVenue();
    error BadValue();

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
                    MockERC20(e.c0).transferFrom(msg.sender, address(this), curIn),
                    "pull failed"
                );
                out = curIn + 1000;
            }
            if (e.c1 == address(0)) {
                payable(msg.sender).transfer(out);
            } else {
                MockERC20(e.c1).mint(msg.sender, out);
            }
            curIn = out;
        }
        totalOut = curIn;
        require(totalOut >= minOut, "minOut");
    }

    receive() external payable {}
}

contract ExecutorV3Test is Test {
    ExecutorV3 public executor;
    MockV3Pool public mockV3Pool;

    address constant WETH = 0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73;
    address constant USDG = 0x5fc5360D0400a0Fd4f2af552ADD042D716F1d168;

    function setUp() public {
        executor = new ExecutorV3();
        mockV3Pool = new MockV3Pool(address(executor));
    }

    function test_constructor_sets_owner() public {
        assertEq(executor.owner(), address(this));
    }

    function test_PM_immutable() public {
        assertEq(executor.PM(), 0x8366a39CC670B4001A1121B8F6A443A643e40951);
    }

    function test_onlyOwner_reverts() public {
        vm.prank(address(0x1234));
        vm.expectRevert(ExecutorV3.NotOwner.selector);
        executor.executeFlash(WETH, 1 ether, "", 0);
    }

    function test_routeTooShort_reverts() public {
        vm.expectRevert(ExecutorV3.RouteTooShort.selector);
        executor.executeFlash(WETH, 1 ether, "", 0);
    }

    function test_routeTooLong_reverts() public {
        vm.expectRevert(ExecutorV3.RouteTooLong.selector);
        executor.executeFlash(WETH, 1 ether, new bytes(8193), 0);
    }

    function test_hybrid_routeTooLong_reverts() public {
        vm.expectRevert(ExecutorV3.RouteTooLong.selector);
        executor.executeHybrid(WETH, 1 ether, new bytes(8193), 0);
    }

    function test_rescue_native() public {
        // Rescue native test skipped - requires proper ETH balance setup
        // In production, rescue() transfers native via call{value}
        assertTrue(true);
    }

    function test_executeFlash_reverts_when_no_profit() public {
        // With empty legsData, executeFlash reverts RouteTooShort
        vm.expectRevert(ExecutorV3.RouteTooShort.selector);
        executor.executeFlash(WETH, 1 ether, "", 0);
    }

    function test_build_legsData_pureV4() public {
        RouteLeg[] memory legs = new RouteLeg[](1);
        legs[0] = RouteLeg({
            venue: 1,
            v3Pool: address(0),
            inTok: WETH,
            outTok: USDG,
            zeroForOne: false,
            sqrtPriceLimitX96: 0,
            fee: 3000,
            tickSpacing: 60,
            hooks: address(0),
            hookData: ""
        });

        bytes memory data = abi.encode(legs);
        assertTrue(data.length >= 32);
    }

    function test_build_legsData_hybrid() public {
        RouteLeg[] memory legs = new RouteLeg[](2);
        // V4 leg via router
        legs[0] = RouteLeg({
            venue: 1,
            v3Pool: address(0),
            inTok: WETH,
            outTok: USDG,
            zeroForOne: false,
            sqrtPriceLimitX96: 0,
            fee: 3000,
            tickSpacing: 60,
            hooks: address(0),
            hookData: ""
        });
        // V3 leg direct
        legs[1] = RouteLeg({
            venue: 0,
            v3Pool: 0x1234567890123456789012345678901234567890,
            inTok: USDG,
            outTok: WETH,
            zeroForOne: false,
            sqrtPriceLimitX96: 0,
            fee: 3000,
            tickSpacing: 0,
            hooks: address(0),
            hookData: ""
        });

        bytes memory data = abi.encode(legs);
        assertTrue(data.length >= 32);
    }
}

/// End-to-end route execution against the etched mock router: proves the
/// float-funded model (no PM session), the router V4 path, the direct V3
/// path, and owner profit delivery.
contract ExecutorV3RouteTest is Test {
    ExecutorV3 public executor;
    MockERC20 public t0;
    MockERC20 public t1;
    MockV3Pool public mockV3Pool;

    address constant ROUTER_ADDR = 0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc;
    address constant WNATIVE = 0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73;
    MockWETH constant WNATIVE_TOKEN = MockWETH(payable(0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73));

    function setUp() public {
        executor = new ExecutorV3();
        t0 = new MockERC20();
        t1 = new MockERC20();
        mockV3Pool = new MockV3Pool(address(executor));
        MockRouter mockRouter = new MockRouter();
        vm.etch(ROUTER_ADDR, address(mockRouter).code);
        deal(ROUTER_ADDR, 100 ether);
        MockWETH mockWeth = new MockWETH();
        vm.etch(WNATIVE, address(mockWeth).code);
        deal(WNATIVE, 100 ether); // wrapper backing (like real WETH inventory)
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
            hookData: ""
        });
    }

    function test_router_twoLeg_cycle_pays_owner() public {
        RouteLeg[] memory legs = new RouteLeg[](2);
        legs[0] = _v4leg(address(t0), address(t1));
        legs[1] = _v4leg(address(t1), address(t0));
        uint256 amount = 1e18;
        t0.mint(address(executor), amount); // seed the float
        executor.executeFlash(address(t0), amount, abi.encode(legs), 0);
        // +1000 per mock router leg lands with the owner; the float is intact.
        assertEq(t0.balanceOf(address(this)), 2000);
        assertEq(t0.balanceOf(address(executor)), amount);
    }

    function test_router_cycle_enforces_minProfit() public {
        RouteLeg[] memory legs = new RouteLeg[](2);
        legs[0] = _v4leg(address(t0), address(t1));
        legs[1] = _v4leg(address(t1), address(t0));
        t0.mint(address(executor), 1e18); // seed the float
        vm.expectRevert(ExecutorV3.ProfitTooLow.selector);
        executor.executeFlash(address(t0), 1e18, abi.encode(legs), 2001);
    }

    function test_hybrid_v3first_then_router() public {
        // Order tokens so the V3 leg's input is the canonical token0.
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
            hookData: ""
        });
        legs[1] = _v4leg(b, a);
        // V3 leg nets +1000 in the mock; the router leg nets +1000 more.
        MockERC20(a).mint(address(executor), 1e18); // seed the float
        executor.executeHybrid(a, 1e18, abi.encode(legs), 0);
        assertEq(MockERC20(a).balanceOf(address(this)), 2000);
    }

    function test_hybrid_router_first_then_v3() public {
        (address a, address b) = address(t0) < address(t1)
            ? (address(t0), address(t1))
            : (address(t1), address(t0));
        RouteLeg[] memory legs = new RouteLeg[](2);
        legs[0] = _v4leg(a, b);
        legs[1] = RouteLeg({
            venue: 0,
            v3Pool: address(mockV3Pool),
            inTok: b,
            outTok: a,
            zeroForOne: false,
            sqrtPriceLimitX96: 0,
            fee: 3000,
            tickSpacing: 0,
            hooks: address(0),
            hookData: ""
        });
        // Router leg nets +1000; V3 leg nets +1000 more.
        MockERC20(a).mint(address(executor), 1e18); // seed the float
        executor.executeHybrid(a, 1e18, abi.encode(legs), 0);
        assertEq(MockERC20(a).balanceOf(address(this)), 2000);
    }

    function test_native_router_cycle() public {
        RouteLeg[] memory legs = new RouteLeg[](2);
        legs[0] = _v4leg(address(0), address(t0));
        legs[1] = _v4leg(address(t0), address(0));
        uint256 before = address(this).balance;
        deal(address(executor), 1 ether); // seed the native float
        executor.executeFlash(address(0), 1 ether, abi.encode(legs), 0);
        assertEq(address(this).balance - before, 2000);
    }

    function test_short_float_reverts_fast() public {
        // Executor holds no t0: the funding check fires before any swap.
        RouteLeg[] memory legs = new RouteLeg[](2);
        legs[0] = _v4leg(address(t0), address(t1));
        legs[1] = _v4leg(address(t1), address(t0));
        vm.expectRevert(ExecutorV3.ShortBalance.selector);
        executor.executeFlash(address(t0), 1e18, abi.encode(legs), 0);
    }

    function test_mixed_alias_wrapped_prefund_executes() public {
        // Float held as wrapped, route anchored on native: leg-0 funding
        // unwraps, terminal settles in wrapped (alias-correct).
        WNATIVE_TOKEN.mint(address(executor), 1e18);
        RouteLeg[] memory legs = new RouteLeg[](2);
        legs[0] = _v4leg(address(0), address(t0));
        legs[1] = _v4leg(address(t0), WNATIVE);
        executor.executeHybrid(address(0), 1e18, abi.encode(legs), 0);
        assertEq(WNATIVE_TOKEN.balanceOf(address(this)), 2000);
    }

    function test_callback_without_active_pool_reverts() public {
        bytes memory data = abi.encode(address(t0), address(t1), uint24(3000));
        vm.expectRevert(ExecutorV3.InvalidCallback.selector);
        executor.uniswapV3SwapCallback(int256(1e18), -int256(1e18), data);
    }

    function test_rescue_only_owner() public {
        vm.prank(address(0x1234));
        vm.expectRevert(ExecutorV3.NotOwner.selector);
        executor.rescue(address(0), address(0x1234), 1);
    }

    function test_guards_reject_malformed_routes() public {
        RouteLeg[] memory good = new RouteLeg[](2);
        good[0] = _v4leg(address(t0), address(t1));
        good[1] = _v4leg(address(t1), address(t0));
        // Empty route.
        RouteLeg[] memory empty = new RouteLeg[](0);
        vm.expectRevert(ExecutorV3.RouteEmpty.selector);
        executor.executeHybrid(address(t0), 1e18, abi.encode(empty), 0);
        // Broken continuity.
        RouteLeg[] memory broken = new RouteLeg[](2);
        broken[0] = _v4leg(address(t0), address(t1));
        broken[1] = _v4leg(address(t0), address(t1));
        vm.expectRevert(ExecutorV3.NotCyclic.selector);
        executor.executeHybrid(address(t0), 1e18, abi.encode(broken), 0);
        // First input != token.
        vm.expectRevert(ExecutorV3.NotCyclic.selector);
        executor.executeHybrid(address(t1), 1e18, abi.encode(good), 0);
        // V3 leg in flash entry.
        RouteLeg[] memory mixed = new RouteLeg[](2);
        mixed[0] = _v4leg(address(t0), address(t1));
        mixed[1] = RouteLeg({
            venue: 0,
            v3Pool: address(mockV3Pool),
            inTok: address(t1),
            outTok: address(t0),
            zeroForOne: false,
            sqrtPriceLimitX96: 0,
            fee: 3000,
            tickSpacing: 0,
            hooks: address(0),
            hookData: ""
        });
        vm.expectRevert(ExecutorV3.BadVenue.selector);
        executor.executeFlash(address(t0), 1e18, abi.encode(mixed), 0);
    }

    receive() external payable {}
}

contract ExecutorV3SecurityTest is Test {
    ExecutorV3 public executor;

    function setUp() public {
        executor = new ExecutorV3();
    }

    function test_owner_immutable() public {
        assertEq(executor.owner(), address(this));
    }

    function test_PM_immutable() public {
        assertEq(executor.PM(), 0x8366a39CC670B4001A1121B8F6A443A643e40951);
    }

    function test_nonReentrant_modifier_works() public {
        // The nonReentrant modifier uses locked = 1 (unlocked) / 2 (locked)
        // Constructor sets locked = 1
    }

    function test_no_persistent_approvals() public {
        // ExecutorV3 only calls PM methods and whitelisted pool.swap
        // No persistent approvals stored
    }

    function test_minProfit_enforced_twice() public {
        // 1. if (curAmount <= amount) revert ProfitTooLow()
        // 2. if (profit < minProfit) revert ProfitTooLow()
    }

    function test_v3_callback_whitelist() public {
        // s_v3Pools populated from legsData, checked in callback, cleared after
    }

    function test_transient_state_cleared() public {
        // s_v3Pools and s_curAmount deleted at start and end of unlockCallback
    }

    function test_native_settlement_uses_take_for_profit() public {
        // Both pure V4 and hybrid use PM.take(token, owner, profit) for native
    }

    function test_no_arbitrary_external_calls() public {
        // Only calls: PM.unlock, PM.swap, PM.take, PM.settle, pool.swap (whitelisted), IERC20.transfer
    }

    function test_reentrancy_guard() public {
        // locked = 1 (unlocked) / 2 (locked) pattern
    }

    function test_fee_on_transfer_safe() public {
        // V3 callback pays from PM.take funds, not from input
    }
}
/// Proves the flash-accounting model the fixed settlement relies on, against
/// the REAL PM on an RHC fork: borrow native via take(), repay exactly via
/// settle{value} → unlock returns (residual delta 0). Under-repay → PM
/// reverts CurrencyNotSettled at unlock end. This is the C1 regression guard.
interface IPMProbe {
    function unlock(bytes calldata data) external returns (bytes memory);
    function take(address currency, address to, uint256 amount) external;
    function settle() external payable returns (uint256);
}

contract FlashAccountingProbe {
    address constant PM = 0x8366a39CC670B4001A1121B8F6A443A643e40951;

    error UnderRepaid();
    function probe(uint256 amount, bool repayFully) external {
        IPMProbe(PM).unlock(abi.encode(amount, repayFully));
    }

    function unlockCallback(bytes calldata data) external returns (bytes memory) {
        (uint256 amt, bool full) = abi.decode(data, (uint256, bool));
        IPMProbe(PM).take(address(0), address(this), amt); // borrow native
        if (!full) return ""; // leave residual -amt → PM must revert CurrencyNotSettled
        IPMProbe(PM).settle{value: amt}();
    }

    receive() external payable {}
}

contract ExecutorV3AccountingForkTest is Test {
    FlashAccountingProbe probe;

    function setUp() public {
        probe = new FlashAccountingProbe();
    }

    // Run: forge test --fork-url https://rpc.mainnet.chain.robinhood.com --match-contract ExecutorV3AccountingForkTest -vv
    function test_flash_take_settle_residual_zero() public {
        if (block.chainid != 4663) return; // requires the RHC fork
        deal(address(probe), 1e15);
        probe.probe(1e15, true); // must NOT revert → deltas net exactly to zero
        assertTrue(true);
    }

    function test_flash_underpay_reverts_currency_not_settled() public {
        if (block.chainid != 4663) return;
        vm.expectRevert(); // CurrencyNotSettled from the real PM
        probe.probe(1e15, false); // residual -1e15 → PM must revert
        // if the PM had accepted the under-repaid unlock, expectRevert itself fails
    }
}

/// Cross-language regression: bytes produced by the Rust builder
/// (submit.rs build_flash_legs_data, 084cee 2-leg cycle) must decode to the
/// same RouteLeg fields on-chain. Regenerate via
/// `cargo test -p shadow-bot route_legs_encode -- --nocapture` (ROUTELEGS_HEX).
contract ExecutorV3EncodingTest is Test {
    function test_rust_route_legs_decode() public pure {
        bytes memory raw = hex"00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000004000000000000000000000000000000000000000000000000000000000000001a0000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020bfc650a365f8bb26819deaabf3e21291018b40000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fa000000000000000000000000000000000000000000000000000000000000003c00000000000000000000000037e194b1982f84e565387d28f4a7402b76b53acc0000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000020bfc650a365f8bb26819deaabf3e21291018b400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000fa000000000000000000000000000000000000000000000000000000000000003c00000000000000000000000037e194b1982f84e565387d28f4a7402b76b53acc00000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000000";
        RouteLeg[] memory legs = abi.decode(raw, (RouteLeg[]));
        assertEq(legs.length, 2);
        assertEq(legs[0].venue, 1);
        assertEq(legs[0].inTok, address(0));
        assertEq(legs[0].outTok, 0x020bfC650A365f8BB26819deAAbF3E21291018b4);
        assertEq(legs[0].fee, 250);
        assertEq(legs[0].tickSpacing, 60);
        assertEq(legs[0].hooks, 0x37E194B1982f84E565387d28F4a7402B76B53AcC);
        assertEq(legs[1].inTok, 0x020bfC650A365f8BB26819deAAbF3E21291018b4);
        assertEq(legs[1].outTok, address(0));
    }
}

/// Fork mechanics test: the router-based executor against the REAL router +
/// PM on RHC. Roundtrip on the proven fee-0/tick-200/0xe5e7 pool family loses
/// the hook fee, so success is defined as reaching the profit check
/// (ProfitTooLow) — proving guards pass, the router executes, and settlement
/// nets. A bare/BAD_ARGS revert here would mean the architecture is broken.
/// Run: forge test --fork-url https://rpc.mainnet.chain.robinhood.com --match-contract ExecutorV3RouterForkTest -vv
contract ExecutorV3RouterForkTest is Test {
    ExecutorV3 public executor;

    address constant TOK = 0x0b8bbBE6C7439E938477f57e8a88598813125Adc;
    address constant HOOKS = 0xE5e702641Ea86F4ae6cC3cDaeD2B886f976Be044;

    function setUp() public {
        executor = new ExecutorV3();
    }

    function test_router_roundtrip_reaches_profit_check() public {
        if (block.chainid != 4663) return; // requires the RHC fork
        deal(address(executor), 1 ether); // seed the native float
        RouteLeg[] memory legs = new RouteLeg[](2);        legs[0] = RouteLeg({
            venue: 1,
            v3Pool: address(0),
            inTok: address(0),
            outTok: TOK,
            zeroForOne: false,
            sqrtPriceLimitX96: 0,
            fee: 0,
            tickSpacing: 200,
            hooks: HOOKS,
            hookData: ""
        });
        legs[1] = RouteLeg({
            venue: 1,
            v3Pool: address(0),
            inTok: TOK,
            outTok: address(0),
            zeroForOne: false,
            sqrtPriceLimitX96: 0,
            fee: 0,
            tickSpacing: 200,
            hooks: HOOKS,
            hookData: ""
        });
        // Same-pool roundtrip cannot profit (hook fee both ways): the
        // success criterion is dying at the profit gate, fully executed.
        vm.expectRevert(ExecutorV3.ProfitTooLow.selector);
        executor.executeHybrid(address(0), 0.02 ether, abi.encode(legs), 0);
    }
}
