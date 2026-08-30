// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title RHC Arbitrage Executor — Robinhood Chain (4663)
/// @notice Borrow → route via RHC router 0x650… → repay → profit.
///         Hard constraints: SECURITY.md budget $100, no `eth_call` per quote, gate `simulated_profit > gas_cost/expected_win_rate`.
///         Security: authenticate callbacks, bound routes, enforce repayment + minProfit on-chain, fee-on-transfer aware, reentrancy guarded.
contract Executor {
    address public immutable owner;
    address public immutable vault; // Balancer V2 vault (or address(0) for funded-caller mode)
    address public constant ROUTER = 0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc;
    address public constant PM = 0x8366a39CC670B4001A1121B8F6A443A643e40951;

    uint256 private locked = 1;

    error NotOwner();
    error NotVault();
    error Reentrancy();
    error RouteTooLong();
    error ZeroProfit();
    error RepayFailed();
    error ProfitTooLow();
    error ArbitraryTargetBlocked();

    event Executed(uint256 profit, address token, uint256 amountIn);

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

    constructor(address _vault) {
        owner = msg.sender;
        vault = _vault;
    }

    // --- Flash loan entry (Balancer V2: flashLoan) ---
    struct Route {
        uint8 venueType;
        address currency0;
        address currency1;
        address pool;
        uint24 fee;
        int24 tickSpacing;
        address hooks;
        bytes hookData;
        address poolManager;
        bytes32 poolKey;
    }

    /// @notice Owner-only entry: flash-borrow `amount` of `token`, execute `routerData` (0x4d819a2a calldata), repay.
    /// @param token flash loan token (must be one of the route's currencies)
    /// @param amount flash loan amount (optimalInput from v2-math, capped to single-tick capacity)
    /// @param routerData exact calldata for ROUTER.swap((Route[]),address,uint256,uint256,uint256) — built by payload_builder
    /// @param minProfit minimum net profit in `token` after repayment (enforces submission gate on-chain)
    function execute(
        address token,
        uint256 amount,
        bytes calldata routerData,
        uint256 minProfit
    ) external onlyOwner nonReentrant {
        if (routerData.length > 8192) revert RouteTooLong();
        if (routerData.length < 4 || bytes4(routerData[:4]) != bytes4(0x4d819a2a)) revert ArbitraryTargetBlocked();

        // Bound: routerData must target ROUTER only — no arbitrary external calls.
        // We do not allow other selectors or targets; the executor only calls ROUTER.
        // Profit and repayment are checked in the callback; reverts there revert here atomically.

        // Initiate flash loan if vault set; else funded-caller path (not used for flash mode)
        if (vault != address(0)) {
            // Balancer V2: vault.flashLoan(this, tokens, amounts, userData)
            // userData carries routerData + minProfit + token for callback validation
            bytes memory userData = abi.encode(routerData, minProfit, token);
            address[] memory tokens = new address[](1);
            tokens[0] = token;
            uint256[] memory amounts = new uint256[](1);
            amounts[0] = amount;
            // solhint-disable-next-line avoid-low-level-calls
            (bool ok,) = vault.call(
                abi.encodeWithSignature("flashLoan(address,address[],uint256[],bytes)", address(this), tokens, amounts, userData)
            );
            if (!ok) revert RepayFailed();
        } else {
            // Funded-caller fallback: caller must have funded this contract beforehand
            _executeRoute(token, amount, routerData, minProfit);
        }
    }

    /// @notice Balancer V2 callback — only vault may call
    /// @dev Reentrancy allowed from `execute` (locked==2) — do not use nonReentrant here.
    function receiveFlashLoan(
        address[] calldata tokens,
        uint256[] calldata amounts,
        uint256[] calldata feeAmounts,
        bytes calldata userData
    ) external {
        if (msg.sender != vault) revert NotVault();
        if (locked != 2) revert Reentrancy();
        (bytes memory routerData, uint256 minProfit, address token) = abi.decode(userData, (bytes, uint256, address));
        uint256 amount = amounts[0];
        uint256 fee = feeAmounts[0];
        // token sanity: must match flash loan token
        if (tokens[0] != token) revert ArbitraryTargetBlocked();

        uint256 profit = _executeRoute(token, amount, routerData, minProfit);

        // Repay: flash loan + fee (Balancer V2: 0 for this vault, but check generically)
        uint256 repay = amount + fee;
        // enforce minProfit already checked inside _executeRoute; also ensure we can repay
        if (profit + repay < repay) revert ZeroProfit(); // overflow guard

        // Fee-on-transfer aware: check balance, not just amount
        uint256 bal = IERC20(token).balanceOf(address(this));
        if (bal < repay + minProfit) revert ProfitTooLow();

        IERC20(token).transfer(vault, repay);
        // remaining `profit` stays as net; send to owner
        if (profit > 0) {
            IERC20(token).transfer(owner, profit);
        }
        emit Executed(profit, token, amount);
    }

    function _executeRoute(address token, uint256 amount, bytes memory routerData, uint256 minProfit) internal returns (uint256 profit) {
        uint256 balBefore = IERC20(token).balanceOf(address(this));
        // If funded-caller mode, amount should already be funded; for flash mode, flash loan is already in balance
        // Execute router swap — router pulls `amount` via its own logic (WETH wrap / transfer)
        // We approve router to spend up to amount (no persistent approval beyond this call)
        IERC20(token).approve(ROUTER, amount);
        (bool ok,) = ROUTER.call(routerData);
        if (!ok) revert RepayFailed();
        // Clear approval
        IERC20(token).approve(ROUTER, 0);

        uint256 balAfter = IERC20(token).balanceOf(address(this));
        // Profit is balance increase minus flash amount (flash amount is included in balBefore for flash path)
        // For funded path, profit = balAfter - balBefore
        // For flash path, balBefore already includes flash amount, so profit = balAfter - balBefore
        // In both cases we compute net gain; repayment is handled by caller
        if (balAfter <= balBefore) revert ZeroProfit();
        profit = balAfter - balBefore;
        // For flash path, the caller will subtract repay; we just enforce minProfit on net after repay
        // Here we enforce that raw profit covers minProfit (conservative — actual net after fee is checked in callback)
        if (profit < minProfit) revert ProfitTooLow();
    }

    // --- Safety ---
    receive() external payable {}
    function rescue(address token, address to, uint256 amount) external onlyOwner nonReentrant {
        // Only rescue tokens not mid-execution; owner can recover dust but not bypass repayment (locked guards)
        IERC20(token).transfer(to, amount);
    }
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}
