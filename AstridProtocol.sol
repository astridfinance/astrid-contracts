// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "./helpers/Utils.sol";
import "./interfaces/IRestakedETH.sol";
import "./eigenlayer/interfaces/IStrategyManager.sol";
import "./eigenlayer/interfaces/IStrategy.sol";
import "./eigenlayer/interfaces/ISlasher.sol";
import "./eigenlayer/interfaces/IDelegationManager.sol";

contract AstridProtocol is Initializable, UUPSUpgradeable, PausableUpgradeable, AccessControlUpgradeable, ReentrancyGuard {

    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant REBASER_ROLE = keccak256("REBASER_ROLE");

    struct StakedTokenMapping {
        bool whitelisted;
        address restakedTokenAddress;
        address eigenLayerStrategyAddress;
    }
    mapping(address => StakedTokenMapping) public stakedTokens;

    address public eigenLayerStrategyManagerAddress;

    struct ReStakeInfo {
        address staker;
        address stakedTokenAddress;
        uint256 amount;
        uint256 stakedAt;
        uint256 shares;
    }

    struct WithdrawalInfo {
        address withdrawer;
        address restakedTokenAddress;
        uint256 amount;
        uint256 shares;
        bool pending;
        uint32 withdrawalStartBlock;
        uint256 withdrawInitiatedAt;
        uint256 withdrawCompletedAt;
        uint256 nonce;
        bytes32 withdrawalRoot;
    }

    struct ReBaseInfo {
        uint256 restakedTokenTotalSupply;
        uint256 eigenLayerUnderlyingValue;
        uint32 currentBlock;
        uint256 currentTimestamp;
    }

    mapping(address => ReStakeInfo[]) public restakes;
    mapping(address => WithdrawalInfo[]) public withdrawals;
    uint96 public withdrawalsNonce;

    event EigenLayerStrategyManagerAddressSet(address oldAddress, address newAddress);
    event StakedTokenMappingSet(address stakedTokenAddress, bool whitelisted, address restakedTokenAddress, address eigenLayerStrategyAddress);
    event RestakePerformed(address indexed from, address stakedTokenAddress, uint256 amount, uint256 shares);
    event RestakeRewardsPerformed(address indexed from, address stakedTokenAddress, uint256 amount, uint256 shares);
    event WithdrawQueued(address indexed to, address restakedTokenAddress, uint256 amount, uint256 shares, uint256 nonce, bytes32 withdrawalRoot);
    event WithdrawCompleted(address indexed to, uint96 withdrawalIndex);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _eigenLayerStrategyManagerAddr) initializer public {
        __Pausable_init();
        __AccessControl_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
        _grantRole(UPGRADER_ROLE, msg.sender);
        _grantRole(REBASER_ROLE, msg.sender);

        eigenLayerStrategyManagerAddress = _eigenLayerStrategyManagerAddr;
    }

    function setEigenLayerStrategyManagerAddress(
        address _eigenLayerStrategyManagerAddr
    ) public whenNotPaused onlyRole(DEFAULT_ADMIN_ROLE) {
        emit EigenLayerStrategyManagerAddressSet(eigenLayerStrategyManagerAddress, _eigenLayerStrategyManagerAddr);

        eigenLayerStrategyManagerAddress = _eigenLayerStrategyManagerAddr;
    }

    function setStakedTokenMapping(
        address _stakedTokenAddr,
        bool _whitelisted,
        address _restakedTokenAddr,
        address _eigenLayerStrategyAddr
    ) public whenNotPaused onlyRole(DEFAULT_ADMIN_ROLE) {
        stakedTokens[_stakedTokenAddr] = StakedTokenMapping({
            whitelisted: _whitelisted,
            restakedTokenAddress: _restakedTokenAddr,
            eigenLayerStrategyAddress: _eigenLayerStrategyAddr
        });

        emit StakedTokenMappingSet(_stakedTokenAddr, _whitelisted, _restakedTokenAddr, _eigenLayerStrategyAddr);
    }

    function pause() public onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() public onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    /**
     * @dev Method used for upgrading the proxy implementation contract.
     */
    function _authorizeUpgrade(address newImplementation) internal onlyRole(UPGRADER_ROLE) override {
    }

    function restakesLength(address staker) public view returns (uint256) {
        return restakes[staker].length;
    }

    function withdrawalsLength(address withdrawer) public view returns (uint256) {
        return withdrawals[withdrawer].length;
    }

    function pendingWithdrawalsAmount(address _restakedTokenAddress, address withdrawer) public view returns (uint256) {
        uint256 pendingAmount = 0;

        for (uint256 i = 0; i < withdrawals[withdrawer].length; i++) {
            if (withdrawals[withdrawer][i].restakedTokenAddress == _restakedTokenAddress && withdrawals[withdrawer][i].pending) {
                pendingAmount += withdrawals[withdrawer][i].amount;
            }
        }

        return pendingAmount;
    }

    /**
     * Only used for rebaseable staked tokens like stETH, whereas rETH and cbETH are non-rebaseable staked tokens.
     * When stETH is rebased (daily), the underlying value in StrategyStEth for this contract will also increase/decrease.
     * Hence we use this function to get the difference and call the `rebase` function on restaked stETH token.
     */
    function rebaseInfo(address _stakedTokenAddress) public view returns (ReBaseInfo memory) {
        StakedTokenMapping memory stakedTokenMapping = stakedTokens[_stakedTokenAddress];

        ReBaseInfo memory info = ReBaseInfo({
            restakedTokenTotalSupply: IRestakedETH(stakedTokenMapping.restakedTokenAddress).totalSupply(),
            eigenLayerUnderlyingValue: IStrategy(stakedTokenMapping.eigenLayerStrategyAddress).userUnderlyingView(address(this)),
            currentBlock: uint32(block.number),
            currentTimestamp: block.timestamp
        });

        return info;
    }

    function restake(address _stakedTokenAddress, uint256 amount) public nonReentrant whenNotPaused returns (uint256) {
        StakedTokenMapping memory stakedTokenMapping = stakedTokens[_stakedTokenAddress];

        require(stakedTokenMapping.whitelisted, "AstridProtocol: Staked token not whitelisted");
        require(IERC20(_stakedTokenAddress).balanceOf(msg.sender) >= amount, "AstridProtocol: Insufficient balance of staked token");
        require(IERC20(_stakedTokenAddress).allowance(msg.sender, address(this)) >= amount, "AstridProtocol: Insufficient allowance of staked token");

        // receive staked token from user
        bool amountSent = Utils.payMe(msg.sender, amount, _stakedTokenAddress);
        require(amountSent, "AstridProtocol: Failed to send staked token");

        // send staked token to EigenLayer on behalf of current contract
        IERC20(_stakedTokenAddress).approve(eigenLayerStrategyManagerAddress, amount);
        uint256 shares = IStrategyManager(eigenLayerStrategyManagerAddress).depositIntoStrategy(IStrategy(stakedTokenMapping.eigenLayerStrategyAddress), IERC20(_stakedTokenAddress), amount);

        // mint restaked token to user
        IRestakedETH(stakedTokenMapping.restakedTokenAddress).mint(msg.sender, amount);

        // save stake info
        restakes[msg.sender].push(ReStakeInfo({
            staker: msg.sender,
            stakedTokenAddress: _stakedTokenAddress,
            amount: amount,
            stakedAt: block.timestamp,
            shares: shares
        }));

        // emit staked performed event
        emit RestakePerformed(msg.sender, _stakedTokenAddress, amount, shares);

        return shares;
    }

    function restakeRewards(address _stakedTokenAddress, uint256 amount) public nonReentrant whenNotPaused onlyRole(REBASER_ROLE) returns (uint256) {
        StakedTokenMapping memory stakedTokenMapping = stakedTokens[_stakedTokenAddress];

        require(stakedTokenMapping.whitelisted, "AstridProtocol: Staked token not whitelisted");
        require(IERC20(_stakedTokenAddress).balanceOf(msg.sender) >= amount, "AstridProtocol: Insufficient balance of staked token");
        require(IERC20(_stakedTokenAddress).allowance(msg.sender, address(this)) >= amount, "AstridProtocol: Insufficient allowance of staked token");

        // receive staked token from user
        bool amountSent = Utils.payMe(msg.sender, amount, _stakedTokenAddress);
        require(amountSent, "AstridProtocol: Failed to send staked token");

        // send staked token to EigenLayer on behalf of current contract
        IERC20(_stakedTokenAddress).approve(eigenLayerStrategyManagerAddress, amount);
        uint256 shares = IStrategyManager(eigenLayerStrategyManagerAddress).depositIntoStrategy(IStrategy(stakedTokenMapping.eigenLayerStrategyAddress), IERC20(_stakedTokenAddress), amount);

        // emit rewards staked performed event
        emit RestakeRewardsPerformed(msg.sender, _stakedTokenAddress, amount, shares);

        return shares;
    }

    function queueWithdrawal(address _restakedTokenAddress, uint256 amount) public nonReentrant whenNotPaused returns (uint96) {
        address _stakedTokenAddress = IRestakedETH(_restakedTokenAddress).stakedTokenAddress();
        StakedTokenMapping memory stakedTokenMapping = stakedTokens[_stakedTokenAddress];

        require(stakedTokenMapping.whitelisted, "AstridProtocol: Staked token not whitelisted");
        require(IERC20(_restakedTokenAddress).balanceOf(msg.sender) >= amount, "AstridProtocol: Insufficient balance of restaked token");
        require(IERC20(_restakedTokenAddress).allowance(msg.sender, address(this)) >= amount, "AstridProtocol: Insufficient allowance of restaked token");

        uint256 shares = IStrategy(stakedTokenMapping.eigenLayerStrategyAddress).underlyingToShares(amount);

        uint256[] memory strategyIndexesArr = new uint256[](1);
        strategyIndexesArr[0] = 1;
        IStrategy[] memory strategiesArr = new IStrategy[](1);
        strategiesArr[0] = IStrategy(stakedTokenMapping.eigenLayerStrategyAddress);
        uint256[] memory sharesArr = new uint256[](1);
        sharesArr[0] = shares;

        bytes32 withdrawalRoot = IStrategyManager(eigenLayerStrategyManagerAddress).queueWithdrawal(
            strategyIndexesArr,
            strategiesArr,
            sharesArr,
            address(this),
            false
        );

        WithdrawalInfo memory withdrawalInfo = WithdrawalInfo({
            withdrawer: msg.sender,
            restakedTokenAddress: _restakedTokenAddress,
            amount: amount,
            shares: shares,
            pending: true,
            withdrawalStartBlock: uint32(block.number),
            withdrawInitiatedAt: block.timestamp,
            withdrawCompletedAt: 0,
            nonce: withdrawalsNonce,
            withdrawalRoot: withdrawalRoot
        });
        withdrawals[msg.sender].push(withdrawalInfo);

        emit WithdrawQueued(msg.sender, _restakedTokenAddress, amount, shares, withdrawalsNonce, withdrawalRoot);

        withdrawalsNonce += 1;

        IRestakedETH(_restakedTokenAddress).burn(msg.sender, withdrawalInfo.amount);

        return withdrawalsNonce - 1;
    }

    function withdrawalDelayBlocks() public view returns (uint32) {
        return uint32(IStrategyManager(eigenLayerStrategyManagerAddress).withdrawalDelayBlocks());
    }

    function canWithdraw(uint96 withdrawalIndex, uint256 middlewareTimesIndex) external view returns (bool) {
        WithdrawalInfo memory withdrawalInfo = withdrawals[msg.sender][withdrawalIndex];
        if (withdrawalInfo.withdrawalStartBlock + withdrawalDelayBlocks() > uint32(block.number)) {
            return false;
        }
        address operator = IDelegationManager(IStrategyManager(eigenLayerStrategyManagerAddress).delegation()).delegatedTo(address(this));
        return ISlasher(IStrategyManager(eigenLayerStrategyManagerAddress).slasher()).canWithdraw(operator, withdrawalInfo.withdrawalStartBlock, middlewareTimesIndex);
    }

    function completeQueuedWithdrawal(uint96 withdrawalIndex, uint256 middlewareTimesIndex) public nonReentrant whenNotPaused {
        WithdrawalInfo memory withdrawalInfo = withdrawals[msg.sender][withdrawalIndex];

        require(withdrawalInfo.withdrawCompletedAt == 0, "AstridProtocol: Withdrawal already completed");
        require(withdrawalInfo.withdrawer == msg.sender, "AstridProtocol: Invalid withdrawer");

        address _stakedTokenAddress = IRestakedETH(withdrawalInfo.restakedTokenAddress).stakedTokenAddress();

        uint256[] memory strategyIndexesArr = new uint256[](1);
        strategyIndexesArr[0] = 1;
        IStrategy[] memory strategiesArr = new IStrategy[](1);
        strategiesArr[0] = IStrategy(stakedTokens[_stakedTokenAddress].eigenLayerStrategyAddress);
        uint256[] memory sharesArr = new uint256[](1);
        sharesArr[0] = withdrawalInfo.shares;

        address operator = IDelegationManager(IStrategyManager(eigenLayerStrategyManagerAddress).delegation()).delegatedTo(address(this));

        IStrategyManager.QueuedWithdrawal memory queuedWithdrawal = IStrategyManager.QueuedWithdrawal({
            strategies: strategiesArr,
            shares: sharesArr,
            depositor: address(this),
            withdrawerAndNonce: IStrategyManager.WithdrawerAndNonce({
                withdrawer: address(this),
                nonce: uint96(withdrawalInfo.nonce)
            }),
            withdrawalStartBlock: withdrawalInfo.withdrawalStartBlock,
            delegatedAddress: operator
        });

        IERC20[] memory tokens = new IERC20[](1);
        tokens[0] = IERC20(_stakedTokenAddress);

        uint256 balanceBefore = IERC20(_stakedTokenAddress).balanceOf(address(this));
        IStrategyManager(eigenLayerStrategyManagerAddress).completeQueuedWithdrawal(
            queuedWithdrawal,
            tokens,
            middlewareTimesIndex,
            true
        );
        uint256 balanceAfter = IERC20(_stakedTokenAddress).balanceOf(address(this));

        withdrawals[msg.sender][withdrawalIndex].pending = false;
        withdrawals[msg.sender][withdrawalIndex].withdrawCompletedAt = block.timestamp;

        bool sent = Utils.payDirect(msg.sender, balanceAfter.sub(balanceBefore), _stakedTokenAddress);
        require(sent, "AstridProtocol: Failed to send staked token");

        emit WithdrawCompleted(msg.sender, withdrawalIndex);
    }

}