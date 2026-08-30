// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// Fork-test probe: can ExecutorV3 borrow the input via the PoolManager's
/// flash accounting (unlock → take) and route through the existing router
/// inside the same lock (nested unlock), then settle?
interface IPM {
    function unlock(bytes calldata data) external returns (bytes memory);
    function take(address currency, address to, uint256 amount) external;
    function settle() external payable returns (uint256 paid);
    function sync(address currency) external;
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

contract FlashProbe {
    address constant PM = 0x8366a39CC670B4001A1121B8F6A443A643e40951;
    address constant ROUTER = 0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc;
    address constant WETH = 0x0Bd7D308f8E1639FAb988df18A8011f41EAcAD73;

    error NestingForbidden();
    error RouterReverted(bytes ret);
    error ProbeFailed(string);

    /// Entry: borrow `amount` of `currency` (native = 0x0) via the PM flash
    /// accounting, run `routerData`, then settle the debt.
    function probe(address currency, uint256 amount, bytes calldata routerData)
        external
        payable
        returns (uint256 profit)
    {
        bytes memory data = abi.encode(currency, amount, routerData, msg.sender);
        IPM(PM).unlock(data);
        profit = IERC20(currency == address(0) ? WETH : currency).balanceOf(address(this));
    }

    /// Called by the PM inside the lock.
    function unlockCallback(bytes calldata data) external returns (bytes memory) {
        require(msg.sender == PM, "only PM");
        (address currency, uint256 amount, bytes memory routerData, address owner_) =
            abi.decode(data, (address, uint256, bytes, address));

        // 1. Borrow the input from the PM's own reserves (flash accounting).
        IPM(PM).take(currency, address(this), amount);

        uint256 balBefore = IERC20(currency == address(0) ? WETH : currency).balanceOf(address(this));

        // 2. Route through the proven router. If the PM lock forbids nesting,
        //    this reverts with the router's own unlock error.
        (bool ok, bytes memory ret) = ROUTER.call{value: currency == address(0) ? amount : 0}(routerData);
        if (!ok) revert RouterReverted(ret);

        uint256 balAfter = IERC20(currency == address(0) ? WETH : currency).balanceOf(address(this));
        if (balAfter <= balBefore) revert ProbeFailed("no profit");

        // 3. Repay the flash loan: sync + transfer + settle.
        if (currency == address(0)) {
            // wrap the borrowed native back? borrowed native is spent by the
            // router; repayment comes from the swap output which is WETH.
            // Simplified probe: settle whatever we hold of the borrowed currency.
            IERC20(WETH).transfer(PM, IERC20(WETH).balanceOf(address(this)));
            IPM(PM).settle();
        } else {
            IERC20(currency).transfer(PM, amount);
            IPM(PM).settle();
        }
        // sweep profit to owner
        IERC20(currency == address(0) ? WETH : currency).transfer(owner_, IERC20(currency == address(0) ? WETH : currency).balanceOf(address(this)));
        return "";
    }

    receive() external payable {}
}
