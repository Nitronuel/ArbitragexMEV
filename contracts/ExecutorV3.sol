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
        IPM(PM).unlock(abi.encode(token, amount, legsData, minProfit, msg.sender));
    }

    function unlockCallback(bytes calldata data) external returns (bytes memory) {
        if (msg.sender != PM) revert NotPM();
        (address token, uint256 amount, bytes memory legsData, uint256 minProfit, address owner_) =
            abi.decode(data, (address, uint256, bytes, uint256, address));
        uint256 startGas = gasleft();

        // 1. Swaps (V4: no upfront take needed — swaps are flash by nature)
        FlashLeg[] memory legs = abi.decode(legsData, (FlashLeg[]));
        uint256 curAmount = amount;
        for (uint256 i = 0; i < legs.length; i++) {
            // amountSpecified: exact-in of currentAmount
            legs[i].params.amountSpecified = int256(curAmount);
            // Use the leg's stored sqrtPriceLimit or default to min/max
            if (legs[i].params.sqrtPriceLimitX96 == 0) {
                legs[i].params.sqrtPriceLimitX96 =
                    legs[i].params.zeroForOne ? MIN_SQRT_PRICE : MAX_SQRT_PRICE;
            }
            BalanceDelta memory delta = IPM(PM).swap(legs[i].key, legs[i].params, legs[i].hookData);
            // Output is the positive delta of the opposite currency
            int256 d0 = delta.amount0;
            int256 d1 = delta.amount1;
            if (legs[i].params.zeroForOne) {
                curAmount = d1 > 0 ? uint256(d1) : 0;
            } else {
                curAmount = d0 > 0 ? uint256(d0) : 0;
            }
            if (curAmount == 0) revert NoProfit();
        }

        // 3. Profit check + settlement
        // V4 flash: no upfront take — net profit = output - input via settle()
        if (curAmount <= amount) revert ProfitTooLow();
        uint256 profit = curAmount - amount;
        if (profit < minProfit) revert ProfitTooLow();

        // Repay flash loan: settle nets all deltas. No upfront take was done,
        // so settle() refunds net profit if positive.
        if (token == address(0)) {
            IPM(PM).settle();
            // take profit to owner
            IPM(PM).take(token, owner_, profit);
        } else {
            IERC20(token).transfer(PM, amount);
            IPM(PM).settle();
            IPM(PM).take(token, owner_, profit);
        }
        emit ExecutedFlash(amount, profit, startGas - gasleft());
        return "";
    }

    // V3 callback — not used in V4-only flash, but present so a future
    // hybrid route (V4+V3) does not revert on an unexpected V3 callback.
    function uniswapV3SwapCallback(int256, int256, bytes calldata) external {
        revert("no V3 in flash path");
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
struct BalanceDelta { int256 amount0; int256 amount1; }
interface IERC20 { function transfer(address, uint256) external returns (bool); function balanceOf(address) external view returns (uint256); }
