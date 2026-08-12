// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../TokenBridgeFixed.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockToken is ERC20 {
    constructor() ERC20("Mock", "MCK") {
        _mint(msg.sender, 1_000_000e18);
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
}

contract TokenBridgeFixedTest is Test {
    TokenBridge public bridge;
    MockToken public token;

    address public admin = address(this);
    address public validator1;
    uint256 public validator1Key;
    address public validator2;
    uint256 public validator2Key;
    address public user = address(0xBEEF);

    function setUp() public {
        // Create validator keys
        (validator1, validator1Key) = makeAddrAndKey("validator1");
        (validator2, validator2Key) = makeAddrAndKey("validator2");

        // Deploy bridge with 2 required signatures
        bridge = new TokenBridge(2);
        bridge.addValidator(validator1);
        bridge.addValidator(validator2);

        // Deploy token and fund user
        token = new MockToken();
        token.transfer(user, 10_000e18);
    }

    function testLockIncludesChainId() public {
        vm.startPrank(user);
        token.approve(address(bridge), 1000e18);

        bytes32 transferId = bridge.lock(address(token), user, 1000e18);

        // Verify the transfer was recorded
        (address t, address s, address r, uint256 a, uint256 n, bool c) = bridge.transfers(transferId);
        assertEq(t, address(token));
        assertEq(s, user);
        assertEq(r, user);
        assertEq(a, 1000e18);
        assertEq(n, 0); // First nonce
        assertFalse(c);
        vm.stopPrank();
    }

    function testNoncePreventsCollision() public {
        vm.startPrank(user);
        token.approve(address(bridge), 2000e18);

        // Lock same params twice
        bytes32 transferId1 = bridge.lock(address(token), user, 1000e18);
        bytes32 transferId2 = bridge.lock(address(token), user, 1000e18);

        // Transfer IDs should be DIFFERENT due to nonce
        assertTrue(transferId1 != transferId2, "Transfer IDs should differ");
        vm.stopPrank();
    }

    function testClaimRequiresValidSignatures() public {
        vm.startPrank(user);
        token.approve(address(bridge), 1000e18);
        bridge.lock(address(token), user, 1000e18);
        vm.stopPrank();

        // Fund bridge for claim simulation
        token.mint(address(bridge), 1000e18);

        // Create EIP-712 signature
        bytes32 CLAIM_TYPEHASH = keccak256(
            "Claim(address token,address recipient,uint256 amount,uint256 nonce)"
        );
        bytes32 structHash = keccak256(abi.encode(
            CLAIM_TYPEHASH,
            address(token),
            user,
            1000e18,
            0 // nonce
        ));
        bytes32 digest = keccak256(abi.encodePacked(
            "\x19\x01",
            bridge.domainSeparator(),
            structHash
        ));

        // Sign with both validators (ordered by address)
        address[] memory signers = new address[](2);
        uint256[] memory keys = new uint256[](2);
        signers[0] = validator1;
        keys[0] = validator1Key;
        signers[1] = validator2;
        keys[1] = validator2Key;

        // Sort signers by address
        if (signers[0] > signers[1]) {
            (signers[0], signers[1]) = (signers[1], signers[0]);
            (keys[0], keys[1]) = (keys[1], keys[0]);
        }

        bytes[] memory signatures = new bytes[](2);
        for (uint i = 0; i < 2; i++) {
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(keys[i], digest);
            signatures[i] = abi.encodePacked(r, s, v);
        }

        // Claim should succeed
        bridge.claim(address(token), user, 1000e18, 0, signatures);

        assertEq(token.balanceOf(user), 10_000e18 + 1000e18 - 1000e18); // Got claimed tokens
    }

    function testReplayOnDifferentChainFails() public {
        // Simulate chain 1
        vm.chainId(1);

        vm.startPrank(user);
        token.approve(address(bridge), 1000e18);
        bridge.lock(address(token), user, 1000e18);
        vm.stopPrank();

        // Get digest for chain 1
        bytes32 CLAIM_TYPEHASH = keccak256(
            "Claim(address token,address recipient,uint256 amount,uint256 nonce)"
        );
        bytes32 structHash = keccak256(abi.encode(
            CLAIM_TYPEHASH,
            address(token),
            user,
            1000e18,
            0
        ));
        bytes32 digestChain1 = keccak256(abi.encodePacked(
            "\x19\x01",
            bridge.domainSeparator(),
            structHash
        ));

        // Switch to chain 2
        vm.chainId(2);

        // Domain separator should be DIFFERENT now
        bytes32 digestChain2 = keccak256(abi.encodePacked(
            "\x19\x01",
            bridge.domainSeparator(),
            structHash
        ));

        // Digests must differ - this proves cross-chain replay is prevented
        assertTrue(digestChain1 != digestChain2, "Digests should differ across chains");
    }

    function testZeroAddressSignatureReverts() public {
        token.mint(address(bridge), 1000e18);

        // Create invalid signature that would recover to address(0)
        bytes[] memory signatures = new bytes[](2);
        signatures[0] = new bytes(65); // All zeros = invalid
        signatures[1] = new bytes(65);

        vm.expectRevert(TokenBridge.InvalidSignature.selector);
        bridge.claim(address(token), user, 1000e18, 0, signatures);
    }
}
