// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./ExecutorUUPS.sol";
import "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import "forge-std/Test.sol";

/// Minimal mock ERC20 with open mint (test funding only).
contract MockERC20U {
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

/// Mock router (etched over the real router address): single-element 0x4d819a2a
/// swaps. Recipient must be address(0); pulls exact amountIn; pays +1000.
contract MockRouterU {
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

    error BadRecipient();
    error BadVenue();

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
        for (uint256 i = 0; i < els.length; i++) {
            REl calldata e = els[i];
            if (e.venue != 2) revert BadVenue();
            require(MockERC20U(e.c0).transferFrom(msg.sender, address(this), curIn), "pull failed");
            curIn = curIn + 1000;
            MockERC20U(e.c1).mint(msg.sender, curIn);
        }
        totalOut = curIn;
        require(totalOut >= minOut, "minOut");
    }

    receive() external payable {}
}

/// Mock Morpho Blue with real-Blue mechanics against the UUPS executor.
contract MockBlueU {
    function flashLoan(address token, uint256 assets, bytes calldata data) external {
        require(MockERC20U(token).transfer(msg.sender, assets), "fund failed");
        ExecutorUUPS(payable(msg.sender)).onMorphoFlashLoan(assets, data);
        require(MockERC20U(token).transferFrom(msg.sender, address(this), assets), "pull failed");
    }
}

contract ExecutorUUPSTest is Test {
    address constant ROUTER_ADDR = 0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc;
    address constant MORPHO_ADDR = 0x9D53d5E3bd5E8d4Cbfa6DB1ca238AEA02E651010;

    ExecutorUUPS impl;
    ExecutorUUPS proxy; // via ERC1967Proxy
    MockERC20U t0;
    MockERC20U t1;

    function setUp() public {
        impl = new ExecutorUUPS();
        ERC1967Proxy p = new ERC1967Proxy(
            address(impl), abi.encodeCall(ExecutorUUPS.initialize, (address(this)))
        );
        proxy = ExecutorUUPS(payable(address(p)));
        t0 = new MockERC20U();
        t1 = new MockERC20U();
        MockRouterU mockRouter = new MockRouterU();
        vm.etch(ROUTER_ADDR, address(mockRouter).code);
        MockBlueU mockBlue = new MockBlueU();
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

    function test_initialize_sets_owner_and_rejects_reinit() public {
        assertEq(proxy.owner(), address(this));
        vm.expectRevert();
        proxy.initialize(address(this));
    }

    function test_impl_not_initializable() public {
        // The bare implementation locked its own initializer in the constructor.
        vm.expectRevert();
        impl.initialize(address(this));
    }

    function test_entries_reject_non_owner() public {
        vm.prank(address(0x1234));
        vm.expectRevert();
        proxy.executeMorphoFlash(address(t0), 1 ether, "", 0);
    }

    function test_upgrade_only_owner() public {
        ExecutorUUPS impl2 = new ExecutorUUPS();
        vm.prank(address(0x1234));
        vm.expectRevert();
        proxy.upgradeToAndCall(address(impl2), "");
        // Owner upgrade preserves owner and stays functional.
        proxy.upgradeToAndCall(address(impl2), "");
        assertEq(proxy.owner(), address(this));
        assertEq(proxy.MORPHO(), MORPHO_ADDR);
    }

    function test_morpho_flash_via_proxy_repays_and_pays_owner() public {
        MockERC20U(address(t0)).mint(MORPHO_ADDR, 10e18);
        assertEq(t0.balanceOf(address(proxy)), 0);
        proxy.executeMorphoFlash(address(t0), 1e18, _cycle(address(t0), address(t1)), 0);
        assertEq(t0.balanceOf(address(this)), 2000);
        assertEq(t0.balanceOf(address(proxy)), 0);
        assertEq(t0.balanceOf(MORPHO_ADDR), 10e18);
    }

    function test_morpho_minProfit_via_proxy_keeps_blue_whole() public {
        MockERC20U(address(t0)).mint(MORPHO_ADDR, 10e18);
        vm.expectRevert(ExecutorUUPS.ProfitTooLow.selector);
        proxy.executeMorphoFlash(address(t0), 1e18, _cycle(address(t0), address(t1)), 2001);
        assertEq(t0.balanceOf(MORPHO_ADDR), 10e18);
        assertEq(t0.balanceOf(address(proxy)), 0);
    }

    function test_rescue_owner_only_and_pays_out() public {
        t0.mint(address(proxy), 5e18);
        vm.prank(address(0x1234));
        vm.expectRevert();
        proxy.rescue(address(t0), address(0x1234), 1e18);
        proxy.rescue(address(t0), address(this), 5e18);
        assertEq(t0.balanceOf(address(this)), 5e18);
    }
}
