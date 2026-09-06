// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// ExecutorUUPS — UUPS-upgradeable Morpho-flash + float-funded V3-direct + V4-via-router
/// cycles on RHC (4663).
///
/// Capital: Morpho Blue `flashLoan(token, assets, data)` (free, no fee) is the
/// primary source; the owner-seeded float remains as fallback for tokens Blue
/// does not hold. Every leg spends holdings physically:
/// - V3 legs: direct pool.swap with callback paid from holdings (proven).
/// - V4 legs: single-element call into the RHC router (0x4d819a2a), the only
///   V4 execution path with live volume. Direct PM.swap is NOT used.
/// No PM session is opened anywhere here (the router manages its own), so the
/// ExecutorV3 "flash-around-PM is impossible" finding does not apply: Morpho
/// flash is external to PM — borrow Blue, run legs, repay Blue.
/// Output is measured by balance delta per leg; minProfit is enforced on the
/// final amount; dust leftovers are swept via rescue().
/// Security: owner-only entries, reentrancy-gated, one-shot callback
/// whitelists (V3 pool slot + Morpho active flag, both consumed before any
/// external call in the callback), route-shape guards fail fast, no persistent
/// approvals (router exact-then-clear; Blue exact for the pull-back), no PM
/// debt (CurrencyNotSettled impossible).
/// Storage: V3's transient slots are preserved in order; Morpho state is
/// appended after them so a future UUPS layer keeps the same prefix.
///
/// Upgradeability: UUPS (ERC-1967). Owner-only `upgradeTo`. `_disableInitializers`
/// in constructor. Storage layout is append-only — never reorder, never delete.

/// Morpho Blue on RHC (verified 2026-09-05: official Morpho addresses page,
/// Robinhood Chain tab, morpho-blue v1.0.0; 15,582 bytes onchain;
/// flashLoan(address,uint256,bytes) selector 0xe0232b42 present).
/// Per-chain addresses differ — Ethereum's 0xBBBB… address does NOT apply.

/// Compact route leg. V3 legs execute direct pool.swap; V4 legs execute one
/// router element. Rust builders (submit.rs) encode this exact layout —
/// DO NOT reorder fields (cross-pinned by ExecutorV3EncodingTest).
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

interface IMorpho {
    function flashLoan(address token, uint256 assets, bytes calldata data) external;
}

import "@openzeppelin-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin-upgradeable/access/OwnableUpgradeable.sol";
import "@openzeppelin-upgradeable/utils/ReentrancyGuardUpgradeable.sol";

contract ExecutorUUPS is UUPSUpgradeable, OwnableUpgradeable, ReentrancyGuardUpgradeable {
    address public constant PM = 0x8366a39CC670B4001A1121B8F6A443A643e40951;
    /// RHC router (proxy) for V4 legs.
    address public constant ROUTER = 0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc;
    /// Morpho Blue singleton (free flash lender) on RHC.
    address public constant MORPHO = 0x9D53d5E3bd5E8d4Cbfa6DB1ca238AEA02E651010;
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
    error NotMorpho();
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
    error FlashMismatch();
    error FlashUnsupported();

    event ExecutedFlash(uint256 amountIn, uint256 profit, uint256 gasUsed);
    event ExecutedMorphoFlash(uint256 amountIn, uint256 profit, uint256 gasUsed);
    event Rescued(address indexed token, uint256 amount);

    constructor() {
        _disableInitializers();
    }

    /// @dev Initializes the contract with the owner address.
    function initialize(address _owner) external initializer {
        __Ownable_init(_owner);
        __UUPSUpgradeable_init();
        __ReentrancyGuard_init();
    }

    /// @dev Only the owner can upgrade.
    function _authorizeUpgrade(address) internal override onlyOwner {}

    /// Float-funded entry, V4 legs only. `legsData` = abi.encode(RouteLeg[])
    /// with every leg venue == 1 (V4 via router). `amount` of `token` is spent
    /// from the owner-seeded float; it must be present (ShortBalance
    /// otherwise — fail fast before any swap).
    function executeFlash(
        address token,
        uint256 amount,
        bytes calldata legsData,
        uint256 minProfit
    ) external onlyOwner nonReentrant {
        uint256 startGas = gasleft();
        (uint256 curAmount, address outTok) = _runLegs(token, amount, legsData, false);
        _settleFloat(token, amount, curAmount, outTok, minProfit, startGas);
    }

    /// Float-funded entry, V3-direct + V4-via-router legs. `legsData` =
    /// abi.encode(RouteLeg[]).
    function executeHybrid(
        address token,
        uint256 amount,
        bytes calldata legsData,
        uint256 minProfit
    ) external onlyOwner nonReentrant {
        uint256 startGas = gasleft();
        (uint256 curAmount, address outTok) = _runLegs(token, amount, legsData, true);
        _settleFloat(token, amount, curAmount, outTok, minProfit, startGas);
    }

    /// Morpho-flash entry, V4 legs only. Borrows `amount` of `token` from Blue
    /// (free); the loan + `minProfit` must be covered by the route or the whole
    /// transaction reverts (Blue is never left unpaid). ERC20 only: Blue cannot
    /// lend native, so `token == address(0)` reverts FlashUnsupported.
    function executeMorphoFlash(
        address token,
        uint256 amount,
        bytes calldata legsData,
        uint256 minProfit
    ) external onlyOwner nonReentrant {
        _requestFlash(token, amount, legsData, minProfit, false);
    }

    /// Morpho-flash entry, V3-direct + V4-via-router legs.
    function executeMorphoHybrid(
        address token,
        uint256 amount,
        bytes calldata legsData,
        uint256 minProfit
    ) external onlyOwner nonReentrant {
        _requestFlash(token, amount, legsData, minProfit, true);
    }

    function _requestFlash(
        address token,
        uint256 amount,
        bytes calldata legsData,
        uint256 minProfit,
        bool isHybrid
    ) internal {
        if (token == address(0)) revert FlashUnsupported();
        if (amount == 0) revert NoProfit();
        if (legsData.length < 32) revert RouteTooShort();
        if (legsData.length > 8192) revert RouteTooLong();
        locked = 2;
        s_morphoActive = true;
        IMorpho(MORPHO).flashLoan(
            token, amount, abi.encode(token, amount, legsData, minProfit, isHybrid)
        );
        s_morphoActive = false;
        locked = 1;
    }

    /// Morpho Blue flash-loan callback. Authenticates the lender AND the
    /// in-progress borrow (one-shot flag), runs the legs, approves Blue's
    /// pull-back, and pays profit to the owner. Any shortfall reverts the whole
    /// transaction, so Blue is always repaid atomically.
    function onMorphoFlashLoan(uint256 assets, bytes calldata data) external {
        if (msg.sender != MORPHO) revert NotMorpho();
        if (locked != 2) revert Reentrancy();
        if (!s_morphoActive) revert NotMorpho();
        s_morphoActive = false;
        (address token, uint256 amount, bytes memory legsData, uint256 minProfit, bool isHybrid) =
            abi.decode(data, (address, uint256, bytes, uint256, bool));
        if (assets != amount) revert FlashMismatch();
        uint256 startGas = gasleft();
        (uint256 curAmount, address outTok) = _runLegs(token, amount, legsData, isHybrid);
        if (curAmount <= amount) revert ProfitTooLow();
        uint256 profit = curAmount - amount;
        if (profit < minProfit) revert ProfitTooLow();
        if (outTok != token) {
            if (!_sameToken(outTok, token)) revert NotCyclic();
            if (token == RHC_WNATIVE) {
                IWETH(RHC_WNATIVE).deposit{value: curAmount}();
            } else {
                revert FlashMismatch();
            }
        }
        if (IERC20(token).balanceOf(address(this)) < amount + profit) revert ShortBalance();
        require(IERC20(token).approve(MORPHO, amount), "morpho approve failed");
        require(IERC20(token).transfer(owner(), profit), "profit transfer failed");
        emit ExecutedMorphoFlash(amount, profit, startGas - gasleft());
    }

    /// Shared leg execution for float and flash paths. Validates route shape
    /// BEFORE any swap (fail fast), spends holdings physically leg by leg, and
    /// measures output by balance delta (fee-on-transfer safe). Returns the
    /// terminal amount and currency; settlement is the caller's job.
    function _runLegs(
        address token,
        uint256 amount,
        bytes memory legsData,
        bool isHybrid
    ) internal returns (uint256 curAmount, address outTok) {
        s_curAmount = 0;
        s_activeV3Pool = address(0);
        s_calledBack = false;
        s_expectedOwed = 0;
        s_expectedInTok = address(0);

        if (legsData.length < 32) revert RouteTooShort();
        if (legsData.length > 8192) revert RouteTooLong();

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
        for (uint256 i = 0; i < legs.length; i++) {
            if (legs[i].venue == 0 && (legs[i].inTok == address(0) || legs[i].outTok == address(0))) {
                revert BadVenue();
            }
            if (legs[i].venue == 0 && legs[i].v3Pool == address(0)) revert BadVenue();
        }
        _fundLeg(legs[0].inTok, amount);
        if (_balanceOf(legs[0].inTok) < amount) revert ShortBalance();

        curAmount = amount;

        for (uint256 i = 0; i < legs.length; i++) {
            RouteLeg memory leg = legs[i];
            if (curAmount == 0) revert NoProfit();
            _fundLeg(leg.inTok, curAmount);
            if (leg.venue == 1) {
                curAmount = _routerSwap(leg, curAmount);
            } else {
                if (curAmount > uint256(type(int256).max)) revert NoProfit();
                s_activeV3Pool = leg.v3Pool;
                s_calledBack = false;
                s_expectedOwed = curAmount;
                s_expectedInTok = leg.inTok;
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

        outTok = legs[legs.length - 1].outTok;
        s_activeV3Pool = address(0);
        s_calledBack = false;
        s_expectedOwed = 0;
        s_expectedInTok = address(0);
        s_curAmount = 0;
    }

    function _settleFloat(
        address token,
        uint256 amount,
        uint256 curAmount,
        address outTok,
        uint256 minProfit,
        uint256 startGas
    ) internal {
        if (curAmount <= amount) revert ProfitTooLow();
        uint256 profit = curAmount - amount;
        if (profit < minProfit) revert ProfitTooLow();
        if (outTok == address(0)) {
            if (address(this).balance < amount + profit) revert ShortBalance();
            (bool ok,) = payable(owner()).call{value: profit}("");
            require(ok, "profit transfer failed");
        } else {
            if (IERC20(outTok).balanceOf(address(this)) < amount + profit) revert ShortBalance();
            require(IERC20(outTok).transfer(owner(), profit), "profit transfer failed");
        }
        emit ExecutedFlash(amount, profit, startGas - gasleft());
        s_curAmount = 0;
    }

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

    function _fundLeg(address inTok, uint256 need) internal {
        uint256 have = _balanceOf(inTok);
        if (have >= need) return;
        uint256 short = need - have;
        if (inTok == address(0)) {
            IWETH(RHC_WNATIVE).withdraw(short);
        } else if (inTok == RHC_WNATIVE) {
            IWETH(RHC_WNATIVE).deposit{value: short}();
        } else {
            revert ShortBalance();
        }
        if (_balanceOf(inTok) < need) revert ShortBalance();
    }

    function _sameToken(address a, address b) internal pure returns (bool) {
        if (a == b) return true;
        return
            (a == address(0) && b == RHC_WNATIVE) ||
            (a == RHC_WNATIVE && b == address(0));
    }

    // Per-unlock state for the V3 callback
    uint256 private s_curAmount;
    address private s_activeV3Pool;
    bool private s_calledBack;
    uint256 private s_expectedOwed;
    address private s_expectedInTok;
    // Morpho flash state (appended after V3 slots)
    bool private s_morphoActive;
    // Storage gap for future UUPS upgrades
    uint256[50] private __gap;

    /// V3 swap callback: pays the pool from contract holdings.
    function uniswapV3SwapCallback(
        int256 amount0Delta,
        int256 amount1Delta,
        bytes calldata data
    ) external {
        if (msg.sender != s_activeV3Pool) revert InvalidCallback();
        s_activeV3Pool = address(0);
        s_calledBack = true;

        (address c0, address c1, uint24 fee) = abi.decode(data, (address, address, uint24));
        fee;

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

        int256 outDelta = amount0Delta < 0 ? amount0Delta : amount1Delta;
        uint256 outAmount = uint256(-outDelta);
        s_curAmount = outAmount;

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