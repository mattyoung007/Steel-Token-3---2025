// SPDX-License-Identifier: MIT
// Author SteelDragon 2025

// A secure ERC20 token with initial 3 million supply, owner-controlled
// minting, burning capability, time-based cooldown period between mints
// to prevent rapid supply manipulation, emergency pause functionality,
// advanced security features including reentrancy protection, blacklisting,
// permit functionality for gasless approvals, and comprehensive token recovery.

pragma solidity ^0.8.20;  // Using a stable, widely tested version

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";  // Adds EIP-2612 permit functionality
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";  // Safer token transfers
import "@openzeppelin/contracts/security/Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";  // Role-based access control
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Multicall.sol";  // Enables batched calls for gas efficiency

/**
 * @title Steel3Token
 * @dev Advanced ERC20 token with burning, permit, and pausable features
 * Includes role-based access control, blacklisting, and enhanced security measures
 * Features secure two-step ownership transfer mechanism
 */
contract Steel3Token is ERC20, ERC20Burnable, ERC20Permit, Pausable, AccessControl, ReentrancyGuard, Multicall {
    using SafeERC20 for IERC20;
    
    // Role definitions
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant RECOVERY_ROLE = keccak256("RECOVERY_ROLE");
    bytes32 public constant BLACKLIST_ROLE = keccak256("BLACKLIST_ROLE");
    
    // Define the token name and symbol as constants
    string private constant TOKEN_NAME = "Steel3Token";
    string private constant TOKEN_SYMBOL = "Steel3";

    // Events for better transparency
    event TokensMinted(address indexed to, uint256 amount, address indexed minter);
    event TokensBurned(address indexed from, uint256 amount);
    event CooldownUpdated(uint256 oldCooldown, uint256 newCooldown);
    event TokensRecovered(address indexed tokenAddress, address indexed to, uint256 amount);
    event AddressBlacklisted(address indexed account);
    event AddressUnblacklisted(address indexed account);
    event WebsiteUpdated(string newWebsite);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferCanceled(address indexed previousOwner, address indexed canceledNewOwner);

    // Initial supply minted at deployment - 3 million tokens
    uint256 public constant INITIAL_SUPPLY = 3_000_000 * 10**18;

    // Minting cooldown to prevent flash minting attacks
    uint256 public mintingCooldown = 1 days;
    uint256 public lastMintTimestamp;
    
    // Metadata
    string private _website = "https://yourproject.com";
    
    // Blacklist mapping
    mapping(address => bool) public blacklisted;
    
    // Mint tracking
    uint256 public totalMinted;
    
    // Batch mint limit
    uint256 public batchMintLimit = 1_000_000 * 10**18; // 1 million tokens
    
    // Ownership transfer variables
    address private _pendingOwner;
    uint256 private _ownershipTransferDeadline;
    uint256 public constant OWNERSHIP_TRANSFER_DELAY = 2 days;
    
    // Track the current admin explicitly
    address private _currentAdmin;

    /**
     * @dev Initializes the token with name, symbol, and mints initial supply
     * Sets up roles and assigns them to the deployer
     */
    constructor()
        ERC20(TOKEN_NAME, TOKEN_SYMBOL)
        ERC20Permit(TOKEN_NAME)
        Multicall()
    {
        // Set up roles
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
        _grantRole(RECOVERY_ROLE, msg.sender);
        _grantRole(BLACKLIST_ROLE, msg.sender);
        
        // Set the initial admin
        _currentAdmin = msg.sender;
        
        // Mint initial supply
        _mint(msg.sender, INITIAL_SUPPLY);
        
        // Set initial values
        lastMintTimestamp = block.timestamp;
        totalMinted = INITIAL_SUPPLY;

        emit TokensMinted(msg.sender, INITIAL_SUPPLY, msg.sender);
    }

    /**
     * @notice Initiates the ownership transfer process
     * @param newOwner Address of the new owner
     */
    function transferOwnership(address newOwner) 
        external 
        onlyRole(DEFAULT_ADMIN_ROLE) 
        nonReentrant 
    {
        require(newOwner != address(0), "New owner cannot be zero address");
        require(newOwner != _currentAdmin, "New owner cannot be current owner");
        require(!blacklisted[newOwner], "New owner cannot be blacklisted");
        
        // Set pending owner and deadline
        _pendingOwner = newOwner;
        _ownershipTransferDeadline = block.timestamp + OWNERSHIP_TRANSFER_DELAY;
        
        emit OwnershipTransferStarted(_currentAdmin, newOwner);
    }
    
    /**
     * @notice Cancels a pending ownership transfer
     */
    function cancelOwnershipTransfer() 
        external 
        onlyRole(DEFAULT_ADMIN_ROLE) 
        nonReentrant 
    {
        require(_pendingOwner != address(0), "No pending ownership transfer");
        
        address oldPendingOwner = _pendingOwner;
        _pendingOwner = address(0);
        _ownershipTransferDeadline = 0;
        
        emit OwnershipTransferCanceled(_currentAdmin, oldPendingOwner);
    }
    
    /**
     * @notice Completes the ownership transfer process
     * Can only be called by the pending owner after the delay period
     */
    function acceptOwnership() 
        external 
        nonReentrant 
    {
        require(msg.sender == _pendingOwner, "Only pending owner can accept");
        require(block.timestamp >= _ownershipTransferDeadline, "Transfer delay not met");
        
        address oldOwner = _currentAdmin;
        address newOwner = _pendingOwner;
        
        // Transfer all admin roles to the new owner
        _grantRole(DEFAULT_ADMIN_ROLE, newOwner);
        _grantRole(MINTER_ROLE, newOwner);
        _grantRole(PAUSER_ROLE, newOwner);
        _grantRole(RECOVERY_ROLE, newOwner);
        _grantRole(BLACKLIST_ROLE, newOwner);
        
        // Revoke roles from old owner if not the same as new owner
        _revokeRole(DEFAULT_ADMIN_ROLE, oldOwner);
        _revokeRole(MINTER_ROLE, oldOwner);
        _revokeRole(PAUSER_ROLE, oldOwner);
        _revokeRole(RECOVERY_ROLE, oldOwner);
        _revokeRole(BLACKLIST_ROLE, oldOwner);
        
        // Update the current admin
        _currentAdmin = newOwner;
        
        // Reset pending owner
        _pendingOwner = address(0);
        _ownershipTransferDeadline = 0;
        
        emit OwnershipTransferred(oldOwner, newOwner);
    }
    
    /**
     * @notice Returns the current admin (owner) of the contract
     * @return The address of the current admin
     */
    function getAdmin() public view returns (address) {
        return _currentAdmin;
    }
    
    /**
     * @notice Returns information about pending ownership transfer
     * @return pendingOwner The address of the pending owner
     * @return transferDeadline The timestamp when the transfer can be completed
     * @return isTransferPending Whether there is a pending transfer
     */
    function getPendingOwnershipTransfer() external view returns (
        address pendingOwner,
        uint256 transferDeadline,
        bool isTransferPending
    ) {
        return (
            _pendingOwner,
            _ownershipTransferDeadline,
            _pendingOwner != address(0)
        );
    }

    /**
     * @notice Mints new tokens, respecting cooldown period
     * @param to Address receiving the tokens
     * @param amount Amount of tokens to mint (with 18 decimals)
     */
    function mint(address to, uint256 amount)
        external
        onlyRole(MINTER_ROLE)
        whenNotPaused
        nonReentrant
    {
        _mintTokens(to, amount);
    }

    /**
     * @notice User-friendly function to mint whole tokens without decimal calculation
     * @param to Address receiving the tokens
     * @param wholeTokens Number of whole tokens to mint (e.g., 1000 for 1000 tokens)
     */
    function mintWholeTokens(address to, uint256 wholeTokens)
        external
        onlyRole(MINTER_ROLE)
        whenNotPaused
        nonReentrant
    {
        uint256 amountWithDecimals = wholeTokens * 10**18;
        _mintTokens(to, amountWithDecimals);
    }
    
    /**
     * @dev Internal function to handle token minting with all necessary checks
     * @param to Address receiving the tokens
     * @param amount Amount of tokens to mint (with 18 decimals)
     */
    function _mintTokens(address to, uint256 amount) internal {
        // Security checks
        require(to != address(0), "Cannot mint to zero address");
        require(amount > 0, "Amount must be positive");
        require(!blacklisted[to], "Recipient is blacklisted");
        require(amount <= batchMintLimit, "Exceeds batch mint limit");
        require(block.timestamp >= lastMintTimestamp + mintingCooldown, "Minting cooldown active");

        // Update cooldown timestamp
        lastMintTimestamp = block.timestamp;
        
        // Update total minted amount
        totalMinted += amount;

        // Mint tokens
        _mint(to, amount);

        emit TokensMinted(to, amount, _msgSender());
    }

    /**
     * @notice Override of the ERC20Burnable burn function to add event emission
     * @param amount Amount of tokens to burn (with 18 decimals)
     */
    function burn(uint256 amount) public override whenNotPaused {
        require(!blacklisted[_msgSender()], "Sender is blacklisted");
        super.burn(amount);
        emit TokensBurned(_msgSender(), amount);
    }

    /**
     * @notice User-friendly function to burn whole tokens without decimal calculation
     * @param wholeTokens Number of whole tokens to burn (e.g., 1000 for 1000 tokens)
     */
    function burnWholeTokens(uint256 wholeTokens) public whenNotPaused {
        require(!blacklisted[_msgSender()], "Sender is blacklisted");
        uint256 amountWithDecimals = wholeTokens * 10**18;
        super.burn(amountWithDecimals);
        emit TokensBurned(_msgSender(), amountWithDecimals);
    }

    /**
     * @notice Burns tokens from a specified account (requires allowance)
     * @param account Address to burn from
     * @param amount Amount to burn (with 18 decimals)
     */
    function burnFrom(address account, uint256 amount) public override whenNotPaused {
        require(!blacklisted[_msgSender()], "Sender is blacklisted");
        require(!blacklisted[account], "Account is blacklisted");
        super.burnFrom(account, amount);
        emit TokensBurned(account, amount);
    }

    /**
     * @notice User-friendly function to burn whole tokens from another account without decimal calculation
     * @param account Address to burn from
     * @param wholeTokens Number of whole tokens to burn (e.g., 1000 for 1000 tokens)
     */
    function burnWholeTokensFrom(address account, uint256 wholeTokens) public whenNotPaused {
        require(!blacklisted[_msgSender()], "Sender is blacklisted");
        require(!blacklisted[account], "Account is blacklisted");
        uint256 amountWithDecimals = wholeTokens * 10**18;
        super.burnFrom(account, amountWithDecimals);
        emit TokensBurned(account, amountWithDecimals);
    }

    /**
     * @notice Pauses all token transfers
     */
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /**
     * @notice Unpauses all token transfers
     */
    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /**
     * @notice Updates the minting cooldown period
     * @param newCooldown New cooldown in seconds
     */
    function setMintingCooldown(uint256 newCooldown) external onlyRole(DEFAULT_ADMIN_ROLE) {
        uint256 oldCooldown = mintingCooldown;
        mintingCooldown = newCooldown;
        emit CooldownUpdated(oldCooldown, newCooldown);
    }
    
    /**
     * @notice Updates the batch mint limit
     * @param newLimit New limit in token units (with 18 decimals)
     */
    function setBatchMintLimit(uint256 newLimit) external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(newLimit > 0, "Limit must be positive");
        batchMintLimit = newLimit;
    }
    
    /**
     * @notice Blacklists an address, preventing it from transferring or receiving tokens
     * @param account Address to blacklist
     */
    function blacklist(address account) external onlyRole(BLACKLIST_ROLE) {
        require(account != address(0), "Cannot blacklist zero address");
        require(!hasRole(DEFAULT_ADMIN_ROLE, account), "Cannot blacklist admin");
        require(account != _pendingOwner, "Cannot blacklist pending owner");
        blacklisted[account] = true;
        emit AddressBlacklisted(account);
    }
    
    /**
     * @notice Removes an address from the blacklist
     * @param account Address to unblacklist
     */
    function unblacklist(address account) external onlyRole(BLACKLIST_ROLE) {
        blacklisted[account] = false;
        emit AddressUnblacklisted(account);
    }

    /**
     * @notice Recovers ERC20 tokens accidentally sent to contract
     * @param tokenAddress Address of the token to recover
     * @param to Address to send the recovered tokens to
     * @param amount Amount to recover
     */
    function recoverERC20(address tokenAddress, address to, uint256 amount) 
        external 
        onlyRole(RECOVERY_ROLE) 
        nonReentrant 
    {
        require(tokenAddress != address(0), "Invalid token address");
        require(tokenAddress != address(this), "Cannot recover native token");
        require(to != address(0), "Cannot send to zero address");
        require(amount > 0, "Amount must be positive");

        // Use SafeERC20 for safer transfers
        IERC20 token = IERC20(tokenAddress);
        uint256 balance = token.balanceOf(address(this));
        require(balance >= amount, "Insufficient balance");
        
        emit TokensRecovered(tokenAddress, to, amount);
        token.safeTransfer(to, amount);
    }
    
    /**
     * @notice Returns the website URL of the token
     * @return The website URL as a string
     */
    function website() external view returns (string memory) {
        return _website;
    }
    
    /**
     * @notice Updates the website URL
     * @param newWebsite The new website URL
     */
    function setWebsite(string calldata newWebsite) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _website = newWebsite;
        emit WebsiteUpdated(newWebsite);
    }
    
    /**
     * @notice Returns comprehensive token information
     * @return currentSupply The current total supply of tokens
     * @return nextMintTime The timestamp when next minting is allowed
     * @return isPaused Whether transfers are currently paused
     */
    function getTokenInfo() external view returns (
        uint256 currentSupply,
        uint256 nextMintTime,
        bool isPaused
    ) {
        uint256 cooldownEnd = lastMintTimestamp + mintingCooldown;
        uint256 nextMint = block.timestamp >= cooldownEnd ? block.timestamp : cooldownEnd;
        
        return (
            totalSupply(),
            nextMint,
            paused()
        );
    }

    /**
     * @dev Hook that is called before any transfer of tokens
     * Adds pausable functionality and blacklist checking
     */
    function _update(address from, address to, uint256 amount)
        internal
        override
        whenNotPaused
    {
        require(!blacklisted[from], "Sender is blacklisted");
        require(!blacklisted[to], "Recipient is blacklisted");
        super._update(from, to, amount);
    }
    
    /**
     * @dev Required override for AccessControl
     */
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}