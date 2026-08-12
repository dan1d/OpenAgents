// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title TokenBridge (Fixed)
/// @notice Cross-chain token bridge with multi-validator signature verification.
/// @dev Implements EIP-712 typed data signing to prevent cross-chain replay attacks.
/// @custom:security-contact security@example.com
///
/// @custom:contributor Agent: Claude Code
/// @custom:timestamp 2026-08-12T22:30:00Z
/// @custom:startup Run `forge test` to verify fixes
/// @custom:env Requires Foundry installed
contract TokenBridge is ReentrancyGuard, EIP712 {
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    // EIP-712 type hashes
    bytes32 private constant LOCK_TYPEHASH = keccak256(
        "Lock(address token,address sender,address recipient,uint256 amount,uint256 nonce)"
    );
    bytes32 private constant CLAIM_TYPEHASH = keccak256(
        "Claim(address token,address recipient,uint256 amount,uint256 nonce)"
    );

    struct Transfer {
        address token;
        address sender;
        address recipient;
        uint256 amount;
        uint256 nonce;
        bool claimed;
    }

    address public admin;
    uint256 public requiredSignatures;

    mapping(address => bool) public isValidator;
    mapping(bytes32 => Transfer) public transfers;
    mapping(bytes32 => bool) public processedHashes;

    // FIX: Per-sender nonce to prevent replay and collision
    mapping(address => uint256) public nonces;

    event TokensLocked(
        bytes32 indexed transferId,
        address token,
        address sender,
        address recipient,
        uint256 amount,
        uint256 nonce
    );
    event TokensClaimed(bytes32 indexed transferId, address token, address recipient, uint256 amount);
    event ValidatorAdded(address indexed validator);
    event ValidatorRemoved(address indexed validator);

    error NotAdmin();
    error ZeroAmount();
    error AlreadyProcessed();
    error InsufficientSignatures();
    error InvalidSignature();
    error DuplicateOrUnorderedSignature();
    error NotEnoughValidSignatures();

    modifier onlyAdmin() {
        if (msg.sender != admin) revert NotAdmin();
        _;
    }

    /// @notice Initialize bridge with EIP-712 domain separator
    /// @param _requiredSignatures Minimum validator signatures required
    constructor(uint256 _requiredSignatures) EIP712("TokenBridge", "2") {
        admin = msg.sender;
        requiredSignatures = _requiredSignatures;
    }

    /// @notice Lock tokens on the source chain to initiate a cross-chain transfer.
    /// @param token ERC20 token address.
    /// @param recipient Destination address on the target chain.
    /// @param amount Amount of tokens to bridge.
    /// @return transferId Unique identifier for this transfer
    function lock(address token, address recipient, uint256 amount) external nonReentrant returns (bytes32) {
        if (amount == 0) revert ZeroAmount();

        // FIX: Include nonce to prevent collision when same params used twice
        uint256 currentNonce = nonces[msg.sender]++;

        // FIX: EIP-712 structured hash includes chainId via domain separator
        // and uses nonce to ensure uniqueness
        bytes32 structHash = keccak256(abi.encode(
            LOCK_TYPEHASH,
            token,
            msg.sender,
            recipient,
            amount,
            currentNonce
        ));

        // This hash is chain-specific due to EIP-712 domain separator
        bytes32 transferId = _hashTypedDataV4(structHash);

        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);

        transfers[transferId] = Transfer({
            token: token,
            sender: msg.sender,
            recipient: recipient,
            amount: amount,
            nonce: currentNonce,
            claimed: false
        });

        emit TokensLocked(transferId, token, msg.sender, recipient, amount, currentNonce);

        return transferId;
    }

    /// @notice Claim bridged tokens on the destination chain with validator signatures.
    /// @param token Token address.
    /// @param recipient Recipient address.
    /// @param amount Amount to claim.
    /// @param nonce The nonce from the source chain lock transaction.
    /// @param signatures Array of validator ECDSA signatures (each 65 bytes).
    function claim(
        address token,
        address recipient,
        uint256 amount,
        uint256 nonce,
        bytes[] calldata signatures
    ) external nonReentrant {
        // FIX: EIP-712 typed data hash includes chainId and contract address
        // via the domain separator, preventing cross-chain replay
        bytes32 structHash = keccak256(abi.encode(
            CLAIM_TYPEHASH,
            token,
            recipient,
            amount,
            nonce
        ));
        bytes32 digest = _hashTypedDataV4(structHash);

        if (processedHashes[digest]) revert AlreadyProcessed();
        if (signatures.length < requiredSignatures) revert InsufficientSignatures();

        uint256 validSigs = 0;
        address lastSigner = address(0);

        for (uint256 i = 0; i < signatures.length; i++) {
            // FIX: Use ECDSA.tryRecover which returns (address, error)
            // and properly handles invalid signatures
            (address signer, ECDSA.RecoverError error,) = ECDSA.tryRecover(digest, signatures[i]);

            // FIX: Check for recovery errors AND zero address
            if (error != ECDSA.RecoverError.NoError || signer == address(0)) {
                revert InvalidSignature();
            }

            if (signer <= lastSigner) revert DuplicateOrUnorderedSignature();
            lastSigner = signer;

            if (isValidator[signer]) {
                validSigs++;
            }
        }

        if (validSigs < requiredSignatures) revert NotEnoughValidSignatures();

        processedHashes[digest] = true;

        IERC20(token).safeTransfer(recipient, amount);
        emit TokensClaimed(digest, token, recipient, amount);
    }

    /// @notice Get the EIP-712 domain separator for this contract
    /// @return The domain separator hash
    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @notice Add a validator address
    /// @param validator Address to add as validator
    function addValidator(address validator) external onlyAdmin {
        isValidator[validator] = true;
        emit ValidatorAdded(validator);
    }

    /// @notice Remove a validator address
    /// @param validator Address to remove as validator
    function removeValidator(address validator) external onlyAdmin {
        isValidator[validator] = false;
        emit ValidatorRemoved(validator);
    }
}
