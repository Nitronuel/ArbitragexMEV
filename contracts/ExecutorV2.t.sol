// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./ExecutorV2.sol";
import "forge-std/Test.sol";

contract MockERC20 is IERC20 {
    mapping(address => uint256) public bal;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public isFOT;
    function mint(address to, uint256 amt) external { bal[to] += amt; }
    function setFOT(address a, bool v) external { isFOT[a] = v; }
    function balanceOf(address a) external view returns (uint256) { return bal[a]; }
    function transfer(address to, uint256 amt) external returns (bool) {
        require(bal[msg.sender] >= amt, "insuf");
        uint256 tax = (isFOT[msg.sender] || isFOT[to]) ? amt / 100 : 0;
        bal[msg.sender] -= amt;
        bal[to] += amt - tax;
        return true;
    }
    function approve(address sp, uint256 amt) external returns (bool) { allowance[msg.sender][sp] = amt; return true; }
    function transferFrom(address from, address to, uint256 amt) external returns (bool) {
        require(bal[from] >= amt && allowance[from][msg.sender] >= amt, "from insuf");
        bal[from] -= amt;
        bal[to] += amt;
        allowance[from][msg.sender] -= amt;
        return true;
    }
}

/// Simulates the router: selector-bound `0x4d819a2a`, returns `profitBps` of
/// the delivered input (native or ERC20) to the caller.
contract MockRouter {
    MockERC20 public token;
    uint256 public profitBps = 500; // 5%
    constructor(MockERC20 t) { token = t; }
    fallback() external payable {
        require(msg.sig == bytes4(0x4d819a2a), "bad selector");
        require(msg.data.length >= 32, "short calldata");
        // A completed cycle returns principal + profit in the input asset.
        if (msg.value > 0) {
            uint256 gain = (msg.value * profitBps) / 10000;
            (bool ok,) = msg.sender.call{value: msg.value + gain}("");
            require(ok, "eth back failed");
        } else {
            // ERC20 path: pull approved principal, then return principal + 5%
            uint256 pulled = token.allowance(msg.sender, address(this));
            require(pulled > 0, "nothing approved");
            require(token.transferFrom(msg.sender, address(this), pulled), "pull failed");
            uint256 gain = (pulled * profitBps) / 10000;
            token.mint(address(this), gain);
            require(token.transfer(msg.sender, pulled + gain), "give back failed");
        }
    }
    receive() external payable {}
}

contract ExecutorV2Test is Test {
    receive() external payable {}

    MockERC20 token;
    MockRouter router;
    ExecutorV2 exec;
    address owner;

    function setUp() public {
        owner = address(this);
        token = new MockERC20();
        router = new MockRouter(token);
        address r = 0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc;
        vm.etch(r, address(router).code);
        vm.store(r, bytes32(uint256(0)), bytes32(uint256(uint160(address(token)))));
        vm.store(r, bytes32(uint256(1)), bytes32(uint256(500)));
        vm.deal(r, 100 ether); // mock router must be able to return principal + profit
        exec = new ExecutorV2();
    }

    function _data() internal pure returns (bytes memory) {
        return abi.encodePacked(bytes4(0x4d819a2a), new bytes(96));
    }

    function test_native_input_success() public {
        uint256 balBefore = owner.balance;
        exec.execute{value: 1 ether}(address(0), 1 ether, _data(), 0.04 ether);
        // 5% profit stays in the executor; owner rescues it
        assertEq(address(exec).balance, 1.05 ether);
        exec.rescue(address(0), owner, address(exec).balance);
        assertGt(owner.balance, balBefore);
    }

    function test_erc20_input_success() public {
        token.mint(address(exec), 1 ether);
        exec.execute(address(token), 1 ether, _data(), 0.04 ether);
        assertEq(token.balanceOf(address(exec)), 1.05 ether);
        // approval cleared
        assertEq(token.allowance(address(exec), 0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc), 0);
    }

    function test_min_profit_enforced_on_chain() public {
        exec.execute{value: 1 ether}(address(0), 1 ether, _data(), 0.04 ether);
        vm.expectRevert(ExecutorV2.ProfitTooLow.selector);
        exec.execute{value: 1 ether}(address(0), 1 ether, _data(), 0.06 ether); // only 5% available
    }

    function test_revert_notOwner() public {
        vm.prank(address(0xdead));
        vm.expectRevert(ExecutorV2.NotOwner.selector);
        exec.execute(address(0), 0, _data(), 0);
    }

    function test_revert_badSelector() public {
        bytes memory bad = abi.encodePacked(bytes4(0xdeadbeef), new bytes(32));
        vm.expectRevert(ExecutorV2.ArbitraryTargetBlocked.selector);
        exec.execute(address(0), 0, bad, 0);
    }

    function test_revert_routeTooLong() public {
        bytes memory long = new bytes(9000);
        long[0] = 0x4d; long[1] = 0x81; long[2] = 0x9a; long[3] = 0x2a;
        vm.expectRevert(ExecutorV2.RouteTooLong.selector);
        exec.execute(address(0), 0, long, 0);
    }

    function test_revert_valueMismatch() public {
        vm.expectRevert(ExecutorV2.ZeroProfit.selector);
        exec.execute{value: 0.5 ether}(address(0), 1 ether, _data(), 0);
    }

    function test_revert_routerFailure() public {
        // passes the executor's selector/length checks, but the router
        // reverts on the short payload -> executor surfaces ZeroProfit
        bytes memory bad = abi.encodePacked(bytes4(0x4d819a2a), hex"ff");
        vm.expectRevert(ExecutorV2.ZeroProfit.selector);
        exec.execute{value: 1 ether}(address(0), 1 ether, bad, 0);
    }

    function test_erc20_fee_on_transfer_profitStillPositive() public {
        token.mint(address(exec), 1 ether);
        token.setFOT(address(exec), true); // 1% tax on outbound
        exec.execute(address(token), 1 ether, _data(), 0.01 ether);
        // balance grew despite the tax (router mints 5% of its balance)
        assertGt(token.balanceOf(address(exec)), 1 ether);
    }
}
