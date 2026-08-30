// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./Executor.sol";
import "forge-std/Test.sol";

contract MockERC20 is IERC20 {
    mapping(address => uint256) public bal;
    mapping(address => mapping(address => uint256)) public allowance;
    function mint(address to, uint256 amt) external { bal[to] += amt; }
    function balanceOf(address a) external view returns (uint256) { return bal[a]; }
    function transfer(address to, uint256 amt) external returns (bool) {
        require(bal[msg.sender] >= amt, "insuf");
        // fee-on-transfer simulation: 1% tax if flagged
        uint256 tax = 0;
        if (isFOT[msg.sender] || isFOT[to]) tax = amt / 100;
        bal[msg.sender] -= amt;
        bal[to] += amt - tax;
        return true;
    }
    function approve(address sp, uint256 amt) external returns (bool) { allowance[msg.sender][sp] = amt; return true; }
    mapping(address => bool) public isFOT;
    function setFOT(address a, bool v) external { isFOT[a] = v; }
}

contract MockRouter {
    address public pm = 0x8366a39CC670B4001A1121B8F6A443A643e40951;
    // simple swap: just mint output token to caller (simulate profit)
    MockERC20 public token;
    uint256 public profitBps = 500; // 5% profit
    constructor(MockERC20 _t) { token = _t; }
    fallback() external {
        // selector 0x4d819a2a expected
        require(msg.sig == bytes4(0x4d819a2a), "bad selector");
        // simulate: increase executor balance by profit
        // amountIn is at offset 0xa0 etc — we just mint profit
        // decode amountIn from calldata tail (last 96 bytes: recipient, amountIn, minOut, deadline)
        // simplify: mint 5% of executor's current balance
        uint256 bal = token.balanceOf(msg.sender);
        token.mint(msg.sender, bal * profitBps / 10000);
    }
}

contract MockVault {
    MockERC20 public token;
    constructor(MockERC20 _t) { token = _t; }
    function flashLoan(address to, address[] calldata tokens, uint256[] calldata amounts, bytes calldata userData) external {
        // mint flash amount to executor
        token.mint(to, amounts[0]);
        // call callback
        (bool ok,) = to.call(abi.encodeWithSignature("receiveFlashLoan(address[],uint256[],uint256[],bytes)", tokens, amounts, new uint256[](1), userData));
        require(ok, "callback failed");
        // check repayment: vault should have been repaid amount
        require(token.balanceOf(address(this)) >= amounts[0], "not repaid");
    }
}

contract ExecutorTest is Test {
    MockERC20 token;
    MockRouter router;
    MockVault vault;
    Executor exec;

    function setUp() public {
        token = new MockERC20();
        // deploy router at expected address via etch
        router = new MockRouter(token);
        address r = 0x65050A9b7E5075A2bA5cED7b1b64EE66262c40Dc;
        vm.etch(r, address(router).code);
        // MockRouter storage: slot0=pm, slot1=token, slot2=profitBps
        vm.store(r, bytes32(uint256(1)), bytes32(uint256(uint160(address(token)))));
        vm.store(r, bytes32(uint256(2)), bytes32(uint256(500)));
        vault = new MockVault(token);
        exec = new Executor(address(vault));
        // fund executor for funded path
        token.mint(address(exec), 0);
    }

    function test_success_flash() public {
        bytes memory data = abi.encodePacked(bytes4(0x4d819a2a), new bytes(100));
        // need to make router succeed: we etched override above, but need MockRouter fallback to handle any calldata
        // simplify: call execute with minProfit 0
        token.mint(address(vault), 0);
        exec.execute(address(token), 1000, data, 10);
        assertGt(token.balanceOf(exec.owner()), 0, "profit to owner");
    }

    function test_revert_notOwner() public {
        bytes memory data = abi.encodePacked(bytes4(0x4d819a2a), new bytes(100));
        vm.prank(address(0xdead));
        vm.expectRevert(Executor.NotOwner.selector);
        exec.execute(address(token), 1000, data, 0);
    }

    function test_revert_badSelector() public {
        bytes memory bad = abi.encodePacked(bytes4(0xdeadbeef), new bytes(100));
        vm.expectRevert(Executor.ArbitraryTargetBlocked.selector);
        exec.execute(address(token), 1000, bad, 0);
    }

    function test_revert_routeTooLong() public {
        bytes memory long = new bytes(9000);
        // set selector
        long[0]=0x4d; long[1]=0x81; long[2]=0x9a; long[3]=0x2a;
        vm.expectRevert(Executor.RouteTooLong.selector);
        exec.execute(address(token), 1000, long, 0);
    }

    function test_revert_onlyVaultCallback() public {
        address[] memory t = new address[](1); t[0]=address(token);
        uint256[] memory a = new uint256[](1); a[0]=1000;
        uint256[] memory f = new uint256[](1); f[0]=0;
        vm.expectRevert(Executor.NotVault.selector);
        exec.receiveFlashLoan(t,a,f,"");
    }

    function test_reentrancy_guard() public {
        // locked is internal; test via double flash loan attempt would revert,
        // simplest: ensure locked resets after success
        bytes memory data = abi.encodePacked(bytes4(0x4d819a2a), new bytes(100));
        exec.execute(address(token), 1000, data, 0);
        // second call should still succeed (lock released)
        exec.execute(address(token), 1000, data, 0);
    }
}
