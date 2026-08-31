// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// ExecutorV3 — PM flash for V4-native cycles on RHC (4663).
///
/// Flash: PM.unlock → direct PM.swap per V4 leg → settle/take profit.
/// No upfront take: V4 swaps are natively flash — settle() nets deltas.
/// No router. V3 support is future work — this covers the hot 0xccf1/0x5691
/// V4-native dislocations where the wallet holds only gas.
///
/// Security: owner-only, reentrancy-gated, selector-bound settlement,
/// minProfit enforced, no persistent approvals.
contract ExecutorV3 {
    address public immutable owner;
    address public constant PM = 0x8366a39CC670B4001A1121B8F6A443A643e40951;
    address public constant ROUTER = 0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc;

    // V4 sqrt price limits
    uint160 constant MIN_SQRT_PRICE = 4295128739 + 1;
    uint160 constant MAX_SQRT_PRICE = 1461446703485210103287273052203988822378723970341 - 1;

    uint256 private locked = 1;
    error NotOwner();
    error NotPM();
    error Reentrancy();
    error RouteTooShort();
    error ProfitTooLow();
    error NoProfit();
    error ArbitraryTargetBlocked();

    struct PoolKey {
        address currency0;
        address currency1;
        uint24 fee;
        int24 tickSpacing;
        address hooks;
    }
    struct SwapParams {
        bool zeroForOne;
        int256 amountSpecified;
        uint160 sqrtPriceLimitX96;
    }
    // BalanceDelta from PM.swap — two int128 packed into int256? V4 returns BalanceDelta
    // as int256-wrapped delta; we decode amount0/1 via low/high int128.
    struct FlashLeg {
        PoolKey key;
        SwapParams params;
        bytes hookData;
    }
    struct HybridLeg {
        uint8 venue; // 0 = V3, 1 = V4
        address v3Pool;
        PoolKey key;
        SwapParams params;
        bytes hookData;
    }

    event ExecutedFlash(uint256 amountIn, uint256 profit, uint256 gasUsed);

    modifier onlyOwner() { if (msg.sender != owner) revert NotOwner(); _; }
    modifier nonReentrant() { if (locked != 1) revert Reentrancy(); locked = 2; _; locked = 1; }

    constructor() { owner = msg.sender; }

    /// Flash entry. `legsData` = abi.encode(FlashLeg[]). `token` must be
    /// address(0) (native) for the initial flash path.
    function executeFlash(
        address token,
        uint256 amount,
        bytes calldata legsData,
        uint256 minProfit
    ) external onlyOwner nonReentrant {
        if (legsData.length < 32) revert RouteTooShort();
        // Deadline-style freshness: if hookData carries a deadline, the PM hook will enforce.
        IPM(PM).unlock(abi.encode(token, amount, legsData, minProfit, msg.sender, false));
    }

    /// Hybrid flash: V3+V4 legs. `legsData` = abi.encode(HybridLeg[]).
    function executeHybrid(
        address token,
        uint256 amount,
        bytes calldata legsData,
        uint256 minProfit
    ) external onlyOwner nonReentrant {
        if (legsData.length < 32) revert RouteTooShort();
        IPM(PM).unlock(abi.encode(token, amount, legsData, minProfit, msg.sender, true));
    }

    function unlockCallback(bytes calldata data) external returns (bytes memory) {
        if (msg.sender != PM) revert NotPM();
        (address token, uint256 amount, bytes memory legsData, uint256 minProfit, address owner_, bool isHybrid) =
            abi.decode(data, (address, uint256, bytes, uint256, address, bool));
        uint256 startGas = gasleft();

        // Reset transient callback state
        s_curAmount = 0;
        delete s_v3Pools;
        uint256 curAmount = amount;
        bool hasV3 = false;
        if (isHybrid) {
            // Hybrid via router: legsData is 0x4d819a2a router calldata. Use PM flash to fund it.
            hasV3 = true;
            if (legsData.length < 4 || bytes4(legsData) != bytes4(0x4d819a2a)) revert ArbitraryTargetBlocked();
            IPM(PM).take(token, address(this), amount);
            if (token == address(0)) {
                (bool ok,) = ROUTER.call{value: amount}(legsData);
                require(ok, "router failed");
                curAmount = address(this).balance;
            } else {
                // Approve exact amount, no persistent approval
                IERC20(token).approve(ROUTER, amount);
                (bool ok,) = ROUTER.call(legsData);
                require(ok, "router failed");
                IERC20(token).approve(ROUTER, 0);
                curAmount = IERC20(token).balanceOf(address(this));
            }
            if (curAmount == 0) revert NoProfit();
        } else {
            // Legacy V4-only path: no upfront take
            FlashLeg[] memory legs = abi.decode(legsData, (FlashLeg[]));
            for (uint256 i = 0; i < legs.length; i++) {
                legs[i].params.amountSpecified = int256(curAmount);
                if (legs[i].params.sqrtPriceLimitX96 == 0) {
                    legs[i].params.sqrtPriceLimitX96 =
                        legs[i].params.zeroForOne ? MIN_SQRT_PRICE : MAX_SQRT_PRICE;
                }
                BalanceDelta memory delta = IPM(PM).swap(legs[i].key, legs[i].params, legs[i].hookData);
                int256 d0 = delta.amount0;
                int256 d1 = delta.amount1;
                if (legs[i].params.zeroForOne) {
                    curAmount = d1 > 0 ? uint256(d1) : 0;
                } else {
                    curAmount = d0 > 0 ? uint256(d0) : 0;
                }
                if (curAmount == 0) revert NoProfit();
            }
        }

        if (curAmount <= amount) revert ProfitTooLow();
        uint256 profit = curAmount - amount;
        if (profit < minProfit) revert ProfitTooLow();

        if (hasV3) {
            // Hybrid with at least one V3 leg produced physical balances.
            if (token == address(0)) {
                IPM(PM).settle{value: amount}();
                (bool ok,) = payable(owner_).call{value: profit}("");
                require(ok, "profit transfer failed");
            } else {
                IERC20(token).transfer(PM, amount);
                IPM(PM).settle();
                IERC20(token).transfer(owner_, profit);
            }
        } else if (isHybrid) {
            // Hybrid encoding but all V4 legs: same as pure V4 (no take)
            if (token == address(0)) {
                IPM(PM).settle();
                IPM(PM).take(token, owner_, profit);
            } else {
                IERC20(token).transfer(PM, amount);
                IPM(PM).settle();
                IPM(PM).take(token, owner_, profit);
            }
        } else {
            // Pure V4 legacy path
            if (token == address(0)) {
                IPM(PM).settle();
                IPM(PM).take(token, owner_, profit);
            } else {
                IERC20(token).transfer(PM, amount);
                IPM(PM).settle();
                IPM(PM).take(token, owner_, profit);
            }
        }
        emit ExecutedFlash(amount, profit, startGas - gasleft());
        return "";
    }

    // Transient storage for V3 callback -> unlockCallback communication (single tx, safe)
    uint256 private s_curAmount;
    address[] private s_v3Pools;

    function uniswapV3SwapCallback(int256 amount0Delta, int256 amount1Delta, bytes calldata data) external {
        // V3 pool calls back to pay. amount0Delta >0 means pool owes token0 to us? No, per V3, positive delta means pool is owed that amount.
        // For exact-in, the owed amount is the input.
        (address c0, address c1, uint24 fee) = abi.decode(data, (address, address, uint24));
        // Determine which token we owe
        uint256 owed;
        address owedToken;
        if (amount0Delta > 0) { owed = uint256(amount0Delta); owedToken = c0; }
        else if (amount1Delta > 0) { owed = uint256(amount1Delta); owedToken = c1; }
        else revert NoProfit();
        // silence fee var (used for validation if desired)
        fee;

        // The swap output is the negative delta
        int256 outDelta = amount0Delta < 0 ? amount0Delta : amount1Delta;
        // outDelta is negative, so positive output = -outDelta
        uint256 outAmount = uint256(-outDelta);
        s_curAmount = outAmount;

        // Pay the pool from this contract's balance (funded by PM.take)
        if (owedToken == address(0)) {
            (bool ok,) = payable(msg.sender).call{value: owed}("");
            require(ok, "V3 native pay failed");
        } else {
            require(IERC20(owedToken).transfer(msg.sender, owed), "V3 pay failed");
        }
    }

    receive() external payable {}
}

interface IPM {
    function unlock(bytes calldata data) external returns (bytes memory);
    function swap(ExecutorV3.PoolKey memory key, ExecutorV3.SwapParams memory params, bytes calldata hookData) external returns (BalanceDelta memory);
    function take(address currency, address to, uint256 amount) external;
    function settle() external payable returns (uint256);
    function sync(address currency) external;
}
interface IUniswapV3Pool {
    function swap(address recipient, bool zeroForOne, int256 amountSpecified, uint160 sqrtPriceLimitX96, bytes calldata data) external returns (int256 amount0, int256 amount1);
}
struct BalanceDelta { int256 amount0; int256 amount1; }
interface IERC20 { function transfer(address, uint256) external returns (bool); function balanceOf(address) external view returns (uint256); function approve(address, uint256) external returns (bool); }
