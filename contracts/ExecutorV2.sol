// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title RHC Arbitrage Executor v2 — Robinhood Chain (4663)
/// @notice Funded-caller: owner funds this contract, then execute() runs a
///         router route (native-input or ERC20-input) and keeps the profit.
///         Native input is forwarded to the router as msg.value (matches live
///         router txs where amountIn == tx.value); ERC20 input is approved.
///         v1 (0x9df5afC5998bf5BDe7A0e80a0057f548480A978B) lacked native
///         forwarding and is retired by this deployment.
///         Security: owner-only, selector-bound 0x4d819a2a calldata, 8 KiB
///         cap, on-chain minProfit enforcement, reentrancy guard, no
///         persistent approvals, rescue only by owner.
contract ExecutorV2 {
    address public immutable owner;
    address public constant ROUTER = 0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc;

    uint256 private locked = 1;

    error NotOwner();
    error Reentrancy();
    error RouteTooLong();
    error ZeroProfit();
    error ProfitTooLow();
    error ArbitraryTargetBlocked();
    error TransferFailed();

    event Executed(address indexed token, uint256 amountIn, uint256 profit);

    modifier onlyOwner() {
        if (msg.sender != owner) revert NotOwner();
        _;
    }

    modifier nonReentrant() {
        if (locked != 1) revert Reentrancy();
        locked = 2;
        _;
        locked = 1;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Run one route. `token == address(0)` means native input: the
    ///         attached msg.value (== `amount`) is forwarded to the router.
    ///         ERC20 input: this contract must hold `amount` of `token`.
    /// @param routerData exact router `0x4d819a2a` calldata (payload builder)
    /// @param minProfit minimum net profit in the input asset (wei); enforces
    ///        the submission gate `simulated_profit > gas_cost/expected_win_rate`
    function execute(
        address token,
        uint256 amount,
        bytes calldata routerData,
        uint256 minProfit
    ) external payable onlyOwner nonReentrant {
        if (routerData.length > 8192) revert RouteTooLong();
        if (routerData.length < 4 || bytes4(routerData[:4]) != bytes4(0x4d819a2a))
            revert ArbitraryTargetBlocked();
        if (token == address(0) && msg.value != amount) revert ZeroProfit();

        uint256 profit = _run(token, amount, routerData);
        if (profit < minProfit) revert ProfitTooLow();
        emit Executed(token, amount, profit);
    }

    function _run(address token, uint256 amount, bytes calldata routerData) internal returns (uint256 profit) {
        if (token == address(0)) {
            uint256 balBefore = address(this).balance;
            (bool ok,) = ROUTER.call{value: amount}(routerData);
            if (!ok) revert ZeroProfit();
            profit = address(this).balance - balBefore;
            if (profit == 0) revert ZeroProfit();
        } else {
            uint256 balBefore = IERC20(token).balanceOf(address(this));
            IERC20(token).approve(ROUTER, amount);
            (bool ok,) = ROUTER.call(routerData);
            if (!ok) revert ZeroProfit();
            IERC20(token).approve(ROUTER, 0);
            uint256 balAfter = IERC20(token).balanceOf(address(this));
            if (balAfter <= balBefore) revert ZeroProfit();
            profit = balAfter - balBefore;
        }
    }

    /// @notice Owner rescue of dust or accumulated profit. Guarded against
    ///         mid-execution use by nonReentrant.
    function rescue(address token, address to, uint256 amount) external onlyOwner nonReentrant {
        if (token == address(0)) {
            (bool ok,) = to.call{value: amount}("");
            if (!ok) revert TransferFailed();
        } else {
            IERC20(token).transfer(to, amount);
        }
    }

    receive() external payable {}
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}
