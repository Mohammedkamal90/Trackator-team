// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ITarget { function poke() external; function balanceOf(address a) external view returns (uint256); }
interface IFoo2 { function balanceOf(address a) external returns (uint256); }

// G-01 loops -------------------------------------------------------------
contract Loops {
    uint256 public total; uint256 public after_; uint256 public d; uint256 public tail;
    function forContinue(uint256 n, bool skip) public {
        for (uint256 i = 0; i < n; i++) { if (skip) continue; total += 1; }
    }
    function whileBreak(uint256 x) public { while (x > 0) { total += 1; break; } after_ = 1; }
    function doWhile(uint256 x) public { do { d += 1; } while (x > 5); }
    uint256 public k;
    function forInc(uint256 n, bool c, bool br) public { for (k = 0; k < n; k += 1) { if (c) continue; if (br) break; total += 1; } }
    function forBreak(uint256 n, bool c) public { for (uint256 i = 0; i < n; i++) { if (c) break; tail += 1; } }
}

// G-03 overloads (same arity) --------------------------------------------
contract Overloads {
    uint256 public x; uint256 public y;
    function f(uint256 a) internal { x = a; }
    function f(address a) internal { y = 1; a; }
    function g(uint256 a) public { f(a); }
}

// G-02 unresolved call / unmodeled -----------------------------------------
contract Unresolved {
    uint256 public s;
    function h(uint256 a) public { s = a; missingFn(a); }
}

// G-05 modifiers + base ctor args --------------------------------------------
contract Base { uint256 public cap; constructor(uint256 c) { cap = c; } }
contract ModChild is Base(100) {
    address public owner; uint256 public v;
    modifier twice() { _; _; }
    function bump() public twice { v += 1; }
    function bad() public onlyMissing { v = 5; }
}

// G-06 access classes --------------------------------------------------------
contract AccessCtl {
    address public owner; mapping(address => bool) public isAdmin; mapping(address => mapping(address => uint256)) public allowance_;
    uint256 public a; uint256 public b; uint256 public c; uint256 public e;
    function ifRevertOwner() public { if (msg.sender != owner) revert(); a = 1; }
    function requireOwner() public { require(owner == msg.sender); b = 1; }
    function requireAdmin() public { require(isAdmin[msg.sender]); c = 1; }
    function open() public { e = 1; }
    function pull(address from, uint256 amt) public { require(allowance_[from][msg.sender] >= amt); e = amt; }
    function alwaysReverts() public { require(false); a = 2; }
}

// G-04 truncation fairness ------------------------------------------------------
contract Trunc {
    uint256 public first; uint256 public q; uint256 public r; uint256 public s; uint256 public t; uint256 public u;
    function many(bool a, bool b, bool c2, bool d2, bool e2, bool f2) public {
        if (a) first = 1;
        if (b) q = 1; if (c2) r = 1; if (d2) s = 1; if (e2) t = 1; if (f2) u = 1;
    }
}

// G-07 grouping semantics ------------------------------------------------------------
contract GroupSem {
    uint256 public total; uint256 public s; uint256 public a1; uint256 public b1; ITarget public target;
    function sameEffects(bool flag) public { uint256 tmp; if (flag) { tmp = a1; } else { tmp = b1; } total += 1; tmp; }
    function ordering(bool c) public { if (c) { target.poke(); s = 1; } else { s = 1; target.poke(); } }
}

// G-09 view classification ------------------------------------------------------------
contract ExtView {
    ITarget public router; IFoo2 public foo;
    function viaParam(address t) public { IFoo2(t).balanceOf(msg.sender); }
    function viaDeclaredView() public { router.balanceOf(msg.sender); }
    function viaDeclaredNonView() public { foo.balanceOf(msg.sender); }
}

// G-08 pair model evidence ----------------------------------------------------------------
contract PlainSupply {
    mapping(address => uint256) bal; uint256 total; address public pair;
    function balanceOf(address a) public view returns (uint256) { return bal[a]; }
    function totalSupply() public view returns (uint256) { return total; }
    function mint(uint256 a) public { total += a; bal[msg.sender] += a; }
}

// unchecked blocks (parser ≥0.17 wraps them as { block }) --------------------------------------
contract Unchecked {
    uint256 public u; mapping(address => uint256) bal;
    function dec(uint256 a) public { unchecked { u -= a; bal[msg.sender] += a; } }
}
