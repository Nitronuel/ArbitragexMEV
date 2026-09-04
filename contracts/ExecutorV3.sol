// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// ExecutorV3 — float-funded V3-direct + V4-via-router cycles on RHC (4663).
///
/// No PM flash: RHC's PoolManager reverts nested unlocks (AlreadyUnlocked),
/// and the router opens its own PM session per call, so flash-around-router
/// is impossible and Balancer is undeployed. Instead the owner seeds a small
/// float (native + anchor stables); every leg spends holdings physically:
/// - V3 legs: direct pool.swap with callback paid from holdings (proven).
/// - V4 legs: single-element call into the RHC router (0x4d819a2a), the only
///   V4 execution path with live volume. Direct PM.swap is NOT used.
/// Output is measured by balance delta per leg; minProfit is enforced on the
/// final amount; dust leftovers are swept via rescue().
/// Security: owner-only, reentrancy-gated, route-shape guards fail fast,
/// no persistent approvals, no PM debt (CurrencyNotSettled impossible).

/// RHC router (proxy) for V4 legs. The V4 PoolManager singleton exists at
/// 0x8366a39CC670B4001A1121B8F6A443A643e40951 but direct PM.swap is not
/// used (see header).

/// Compact route leg. V3 legs execute direct pool.swap; V4 legs execute one
/// router element. Rust builders (submit.rs) encode this exact layout.
struct RouteLeg {
    uint8 venue; // 0 = V3 direct, 1 = V4 via router
    address v3Pool; // V3 only
    address inTok; // swap input, 0x0 = native
    address outTok; // swap output, 0x0 = native
    bool zeroForOne; // V3 only
    uint160 sqrtPriceLimitX96; // V3 only, 0 = min/max default
    uint24 fee; // V3: pool fee; V4: router fee field
    int24 tickSpacing; // V4: router field
    address hooks; // V4 only
    bytes hookData; // V4 only
}

/// Single router element (matches 0x4d819a2a layout, round-trip verified).
struct RouterEl {
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

interface IUniswapV3Pool {
    function swap(address recipient, bool zeroForOne, int256 amountSpecified, uint160 sqrtPriceLimitX96, bytes calldata data) external returns (int256 amount0, int256 amount1);
}

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
    function approve(address, uint256) external returns (bool);
}

interface IWETH {
    function deposit() external payable;
    function withdraw(uint256) external;
}

contract ExecutorV3 {
    address public immutable owner;
    address public constant PM = 0x8366a39CC670B4001A1121B8F6A443A643e40951;
    /// RHC router (proxy) for V4 legs.
    address public constant ROUTER = 0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc;
    /// Router entry selector.
    bytes4 constant ROUTER_SWAP_SEL = bytes4(0x4d819a2a);
    /// Wrapped native alias accepted wherever the null sentinel is (comparison only).
    address constant RHC_WNATIVE = 0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73;

    // V4 sqrt price limits
    uint160 constant MIN_SQRT_PRICE = 4295128739 + 1;
    uint160 constant MAX_SQRT_PRICE = 1461446703485210103287273052203988822378723970341 - 1;

    uint256 private locked = 1;
    error NotOwner();
    error NotPM();
    error Reentrancy();
    error RouteTooShort();
    error RouteTooLong();
    error RouteEmpty();
    error BadVenue();
    error NotCyclic();
    error RouterFailed();
    error ProfitTooLow();
    error NoProfit();
    error ShortBalance();
    error InvalidCallback();

    event ExecutedFlash(uint256 amountIn, uint256 profit, uint256 gasUsed);
    event Rescued(address indexed token, uint256 amount);

    modifier onlyOwner() { if (msg.sender != owner) revert NotOwner(); _; }
    modifier nonReentrant() { if (locked != 1) revert Reentrancy(); locked = 2; _; locked = 1; }

    constructor() { owner = msg.sender; }

    /// Funded entry, V4 legs only. `legsData` = abi.encode(RouteLeg[]) with
    /// every leg venue == 1 (V4 via router). `amount` of `token` is spent
    /// from the owner-seeded float; it must be present (ShortBalance
    /// otherwise — fail fast before any swap).
    function executeFlash(
        address token,
        uint256 amount,
        bytes calldata legsData,
        uint256 minProfit
    ) external onlyOwner nonReentrant {
        if (legsData.length < 32) revert RouteTooShort();
        if (legsData.length > 8192) revert RouteTooLong();
        _execute(token, amount, legsData, minProfit, false);
    }

    /// Funded entry, V3-direct + V4-via-router legs. `legsData` =
    /// abi.encode(RouteLeg[]).
    function executeHybrid(
        address token,
        uint256 amount,
        bytes calldata legsData,
        uint256 minProfit
    ) external onlyOwner nonReentrant {
        if (legsData.length < 32) revert RouteTooShort();
        if (legsData.length > 8192) revert RouteTooLong();
        _execute(token, amount, legsData, minProfit, true);
    }

    /// Shared funded-route execution. No PM session is opened anywhere in
    /// this contract (the router manages its own); every leg spends contract
    /// holdings physically, chained output-to-input.
    function _execute(
        address token,
        uint256 amount,
        bytes calldata legsData,
        uint256 minProfit,
        bool isHybrid
    ) internal {
        uint256 startGas = gasleft();
        // Reset transient state.
        s_curAmount = 0;
        s_activeV3Pool = address(0);
        s_calledBack = false;
        s_expectedOwed = 0;
        s_expectedInTok = address(0);

        // Route shape is validated BEFORE any swap so malformed routes fail
        // fast instead of burning gas leg by leg. Token identity is
        // native-alias tolerant (0x0 vs wrapped) via _sameToken.
        RouteLeg[] memory legs = abi.decode(legsData, (RouteLeg[]));
        if (legs.length == 0) revert RouteEmpty();
        if (legs[0].venue > 1) revert BadVenue();
        if (!_sameToken(legs[0].inTok, token)) revert NotCyclic();
        if (!isHybrid) {
            for (uint256 i = 0; i < legs.length; i++) {
                if (legs[i].venue != 1) revert BadVenue();
            }
        }
        for (uint256 i = 1; i < legs.length; i++) {
            if (legs[i].venue > 1) revert BadVenue();
            if (!_sameToken(legs[i].inTok, legs[i - 1].outTok)) revert NotCyclic();
        }
        if (!_sameToken(legs[legs.length - 1].outTok, token)) revert NotCyclic();
        // V3 pools settle in real token contracts (never the 0x0 sentinel).
        for (uint256 i = 0; i < legs.length; i++) {
            if (legs[i].venue == 0 && (legs[i].inTok == address(0) || legs[i].outTok == address(0))) {
                revert BadVenue();
            }
        }
        // First-leg funding comes from the float, converting across the
        // native alias when the other side covers it — fail fast when short.
        _fundLeg(legs[0].inTok, amount);
        if (_balanceOf(legs[0].inTok) < amount) revert ShortBalance();

        // Funded accounting model: every leg spends contract holdings
        // physically, chained output-to-input. No PM session exists, so
        // there is no debt to track — the float check above is the only
        // funding gate.
        uint256 curAmount = amount;

        for (uint256 i = 0; i < legs.length; i++) {
            RouteLeg memory leg = legs[i];
            if (curAmount == 0) revert NoProfit();
            // Alias-mixed routes convert here (wrap/unwrap) or fail fast.
            _fundLeg(leg.inTok, curAmount);
            if (leg.venue == 1) {
                // V4 leg via the router, spent from holdings.
                curAmount = _routerSwap(leg, curAmount);
            } else {
                // V3 leg: direct pool.swap, exact input (positive amount =
                // exact-in on V3 — proven by RHC fork replay), paid from
                // holdings in the callback.
                if (curAmount > uint256(type(int256).max)) revert NoProfit();
                s_activeV3Pool = leg.v3Pool;
                s_calledBack = false;
                s_expectedOwed = curAmount;
                s_expectedInTok = leg.inTok;
                // Callback data carries canonical (sorted) currencies; V3
                // pools use real token addresses (never the 0x0 sentinel).
                (address cc0, address cc1) = leg.inTok < leg.outTok
                    ? (leg.inTok, leg.outTok)
                    : (leg.outTok, leg.inTok);
                IUniswapV3Pool(leg.v3Pool).swap(
                    address(this),
                    leg.zeroForOne,
                    int256(curAmount),
                    leg.sqrtPriceLimitX96 == 0
                        ? (leg.zeroForOne ? MIN_SQRT_PRICE : MAX_SQRT_PRICE)
                        : leg.sqrtPriceLimitX96,
                    abi.encode(cc0, cc1, leg.fee)
                );
                s_activeV3Pool = address(0);
                if (!s_calledBack) revert InvalidCallback();
                curAmount = s_curAmount;
            }
            if (curAmount == 0) revert NoProfit();
        }

        if (curAmount <= amount) revert ProfitTooLow();
        uint256 profit = curAmount - amount;
        if (profit < minProfit) revert ProfitTooLow();

        // Settlement: the float advanced `amount` and now holds
        // `amount + profit` in the terminal leg's currency (alias-correct;
        // native and wrapped are 1:1 for profit denomination). Send the
        // profit to the owner; the float (and any dust) stays for next time.
        address outTok = legs[legs.length - 1].outTok;
        if (outTok == address(0)) {
            if (address(this).balance < amount + profit) revert ShortBalance();
            (bool ok,) = payable(owner).call{value: profit}("");
            require(ok, "profit transfer failed");
        } else {
            if (IERC20(outTok).balanceOf(address(this)) < amount + profit) revert ShortBalance();
            require(IERC20(outTok).transfer(owner, profit), "profit transfer failed");
        }
        emit ExecutedFlash(amount, profit, startGas - gasleft());
        // Clear transient state
        s_activeV3Pool = address(0);
        s_calledBack = false;
        s_expectedOwed = 0;
        s_expectedInTok = address(0);
        s_curAmount = 0;
    }

    /// Execute one V4 leg through the RHC router: single-element 0x4d819a2a
    /// swap with recipient 0x0 (output returns to this contract — any other
    /// recipient reverts BAD_ARGS), minOut 1, deadline 0 (both proven live).
    /// ERC20 input is approved exact-then-cleared; native input is forwarded
    /// as value. Output is measured by balance delta (fee-on-transfer safe).
    /// Returns the received output amount.
    function _routerSwap(RouteLeg memory leg, uint256 amountIn) internal returns (uint256) {
        RouterEl[] memory els = new RouterEl[](1);
        els[0] = RouterEl({
            venue: 2,
            c0: leg.inTok,
            c1: leg.outTok,
            pool: address(0),
            fee: leg.fee,
            tickSpacing: leg.tickSpacing,
            hooks: leg.hooks,
            hookData: leg.hookData,
            pm: PM,
            poolKey: bytes32(0)
        });
        bytes memory cd = abi.encodeWithSelector(
            ROUTER_SWAP_SEL, els, address(0), amountIn, uint256(1), uint256(0)
        );
        uint256 outBefore = _balanceOf(leg.outTok);
        bool ok;
        bytes memory ret;
        if (leg.inTok == address(0)) {
            (ok, ret) = ROUTER.call{value: amountIn}(cd);
        } else {
            require(IERC20(leg.inTok).approve(ROUTER, amountIn), "router approve failed");
            (ok, ret) = ROUTER.call(cd);
            require(IERC20(leg.inTok).approve(ROUTER, 0), "approve clear failed");
        }
        if (!ok) {
            // Bubble the router's reason (BAD_ARGS etc.) for diagnostics.
            assembly {
                revert(add(ret, 32), mload(ret))
            }
        }
        uint256 outAfter = _balanceOf(leg.outTok);
        if (outAfter <= outBefore) revert NoProfit();
        return outAfter - outBefore;
    }

    function _balanceOf(address tok) internal view returns (uint256) {
        return tok == address(0) ? address(this).balance : IERC20(tok).balanceOf(address(this));
    }

    /// Ensure `need` of `inTok` is held, converting across the native alias
    /// when the other side covers it (standard WETH deposit/withdraw, no
    /// callbacks). Anything else fails fast — never a partial fund.
    function _fundLeg(address inTok, uint256 need) internal {
        if (_balanceOf(inTok) >= need) return;
        if (inTok == address(0)) {
            IWETH(RHC_WNATIVE).withdraw(need);
        } else if (inTok == RHC_WNATIVE) {
            IWETH(RHC_WNATIVE).deposit{value: need}();
        } else {
            revert ShortBalance();
        }
        if (_balanceOf(inTok) < need) revert ShortBalance();
    }

    /// Native-alias-tolerant token identity: 0x0 and the wrapped contract
    /// denote the same currency across venue conventions.
    function _sameToken(address a, address b) internal pure returns (bool) {
        if (a == b) return true;
        return
            (a == address(0) && b == RHC_WNATIVE) ||
            (a == RHC_WNATIVE && b == address(0));
    }

    // Per-unlock state for the V3 callback (single slot — scoped to the leg
    // currently swapping, cleared before/after each swap and at unlock end).
    uint256 private s_curAmount;
    address private s_activeV3Pool;
    bool private s_calledBack;
    // Expected callback payment: exact-input means the pool is owed exactly
    // the funded input in the input token — enforced in the callback.
    uint256 private s_expectedOwed;
    address private s_expectedInTok;

    /// V3 swap callback: pays the pool from contract holdings (float-funded).
    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata data
    ) external {
        // One-shot whitelist: only the V3 pool currently being swapped
        // inside our route may call, exactly once. The slot is consumed
        // before paying so a re-enterant pool cannot double-collect.
        if (msg.sender != s_activeV3Pool) revert InvalidCallback();
        s_activeV3Pool = address(0);
        s_calledBack = true;

        (address c0, address c1, uint24 fee) = abi.decode(data, (address, address, uint24));
        fee; // silence unused

        // Positive delta = pool is owed that amount. Exact-input binds it:
        // an honest pool demands exactly the funded input in the input
        // token — anything else is a malicious overcharge, refused here.
        uint256 owed;
        address owedToken;
        if (amount0Delta > 0) {
            owed = uint256(amount0Delta);
            owedToken = c0;
        } else if (amount1Delta > 0) {
            owed = uint256(amount1Delta);
            owedToken = c1;
        } else {
            revert NoProfit();
        }
        if (owed != s_expectedOwed || owedToken != s_expectedInTok) revert InvalidCallback();

        // Output is the negative delta
        int256 outDelta = amount0Delta < 0 ? amount0Delta : amount1Delta;
        uint256 outAmount = uint256(-outDelta);
        s_curAmount = outAmount;

        // Pay the pool from this contract's float balance.
        if (owedToken == address(0)) {
            (bool ok,) = payable(msg.sender).call{value: owed}("");
            require(ok, "V3 native pay failed");
        } else {
            require(IERC20(owedToken).transfer(msg.sender, owed), "V3 pay failed");
        }
    }

    /// Owner rescue of dust or accumulated profit.
    function rescue(address token, address to, uint256 amount) external onlyOwner nonReentrant {
        if (token == address(0)) {
            (bool ok,) = to.call{value: amount}("");
            require(ok, "transfer failed");
        } else {
            require(IERC20(token).transfer(to, amount), "transfer failed");
        }
        emit Rescued(token, amount);
    }

    receive() external payable {}
}