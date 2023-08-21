// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "./helpers/OnChPayable.sol";
import "./interfaces/IRestakedETH.sol";
import "./eigenlayer/interfaces/IStrategyManager.sol";
import "./eigenlayer/interfaces/IStrategy.sol";
import "./eigenlayer/interfaces/ISlasher.sol";
import "./eigenlayer/interfaces/IDelegationManager.sol";

contract AstridProtocol is Initializable, UUPSUpgradeable, PausableUpgradeable, AccessControlUpgradeable, OnChPayable {

    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant REBASER_ROLE = keccak256("REBASER_ROLE");

    address private _stakedTokenAddress;
    address private _restakedTokenAddress;

    address private _eigenLayerStrategyManagerAddress;
    address private _eigenLayerStrategyStEthAddress;

    struct ReStakeInfo {
        address staker;
        uint256 amount;
        uint256 stakedAt;
        uint256 shares;
    }

    struct WithdrawalInfo {
        address withdrawer;
        uint256 amount;
        uint256 shares;
        bool pending;
        uint32 withdrawalStartBlock;
        uint256 withdrawInitiatedAt;
        uint256 withdrawCompletedAt;
        uint256 nonce;
        bytes32 withdrawalRoot;
    }

    mapping(address => ReStakeInfo[]) public restakes;
    mapping(address => WithdrawalInfo[]) public withdrawals;
    mapping(address => mapping(uint96 => WithdrawalInfo)) public withdrawalsByNonce;
    uint96 public withdrawalsNonce;

    event RestakePerformed(address indexed from, uint256 amount, uint256 shares);
    event RestakeRewardsPerformed(address indexed from, uint256 amount, uint256 shares);
    event WithdrawQueued(address indexed to, uint256 amount, uint256 shares, uint256 nonce, bytes32 withdrawalRoot);
    event WithdrawCompleted(address indexed to, uint256 amount, uint256 shares, uint256 nonce, bytes32 withdrawalRoot);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _stakedTokenAddr, address _restakedTokenAddr, address _eigenLayerStrategyManagerAddr, address _eigenLayerStrategyStEthAddr) initializer public {
        __Pausable_init();
        __AccessControl_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
        _grantRole(UPGRADER_ROLE, msg.sender);
        _grantRole(REBASER_ROLE, msg.sender);

        _stakedTokenAddress = _stakedTokenAddr;
        _restakedTokenAddress = _restakedTokenAddr;

        _eigenLayerStrategyManagerAddress = _eigenLayerStrategyManagerAddr;
        _eigenLayerStrategyStEthAddress = _eigenLayerStrategyStEthAddr;
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

    function pendingWithdrawalsAmount(address withdrawer) public view returns (uint256) {
        uint256 pendingAmount = 0;

        for (uint256 i = 0; i < withdrawals[withdrawer].length; i++) {
            if (withdrawals[withdrawer][i].pending) {
                pendingAmount += withdrawals[withdrawer][i].amount;
            }
        }

        return pendingAmount;
    }

    function restake(uint256 amount) public whenNotPaused returns (uint256) {
        require(IERC20(_stakedTokenAddress).balanceOf(msg.sender) >= amount, "AstridProtocol: Insufficient balance of staked token");
        require(IERC20(_stakedTokenAddress).allowance(msg.sender, address(this)) >= amount, "AstridProtocol: Insufficient allowance of staked token");

        // receive staked token from user
        bool amountSent = _payMe(msg.sender, amount, _stakedTokenAddress);
        require(amountSent, "AstridProtocol: Failed to send staked token");

        // send staked token to EigenLayer on behalf of current contract
        IERC20(_stakedTokenAddress).approve(_eigenLayerStrategyManagerAddress, amount);
        uint256 shares = IStrategyManager(_eigenLayerStrategyManagerAddress).depositIntoStrategy(IStrategy(_eigenLayerStrategyStEthAddress), IERC20(_stakedTokenAddress), amount);

        // mint restaked token to user
        IRestakedETH(_restakedTokenAddress).mint(msg.sender, amount);

        // save stake info
        restakes[msg.sender].push(ReStakeInfo({
            staker: msg.sender,
            amount: amount,
            stakedAt: block.timestamp,
            shares: shares
        }));

        // emit staked performed event
        emit RestakePerformed(msg.sender, amount, shares);

        return shares;
    }

    function restakeRewards(uint256 amount) public whenNotPaused onlyRole(REBASER_ROLE) returns (uint256) {
        require(IERC20(_stakedTokenAddress).balanceOf(msg.sender) >= amount, "AstridProtocol: Insufficient balance of staked token");
        require(IERC20(_stakedTokenAddress).allowance(msg.sender, address(this)) >= amount, "AstridProtocol: Insufficient allowance of staked token");

        // receive staked token from user
        bool amountSent = _payMe(msg.sender, amount, _stakedTokenAddress);
        require(amountSent, "AstridProtocol: Failed to send staked token");

        // send staked token to EigenLayer on behalf of current contract
        IERC20(_stakedTokenAddress).approve(_eigenLayerStrategyManagerAddress, amount);
        uint256 shares = IStrategyManager(_eigenLayerStrategyManagerAddress).depositIntoStrategy(IStrategy(_eigenLayerStrategyStEthAddress), IERC20(_stakedTokenAddress), amount);

        // emit rewards staked performed event
        emit RestakeRewardsPerformed(msg.sender, amount, shares);

        return shares;
    }

    function queueWithdrawal(uint256 amount) public whenNotPaused returns (uint96) {
        require(IERC20(_restakedTokenAddress).balanceOf(msg.sender) >= amount, "AstridProtocol: Insufficient balance of restaked token");
        require(IERC20(_restakedTokenAddress).allowance(msg.sender, address(this)) >= amount, "AstridProtocol: Insufficient allowance of restaked token");

        uint256 shares = IStrategy(_eigenLayerStrategyStEthAddress).underlyingToShares(amount);

        uint256[] memory strategyIndexesArr = new uint256[](1);
        strategyIndexesArr[0] = 1;
        IStrategy[] memory strategiesArr = new IStrategy[](1);
        strategiesArr[0] = IStrategy(_eigenLayerStrategyStEthAddress);
        uint256[] memory sharesArr = new uint256[](1);
        sharesArr[0] = shares;

        bytes32 withdrawalRoot = IStrategyManager(_eigenLayerStrategyManagerAddress).queueWithdrawal(
            strategyIndexesArr,
            strategiesArr,
            sharesArr,
            address(this),
            false
        );

        WithdrawalInfo memory withdrawalInfo = WithdrawalInfo({
            withdrawer: msg.sender,
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
        withdrawalsByNonce[msg.sender][withdrawalsNonce] = withdrawalInfo;

        emit WithdrawQueued(msg.sender, amount, shares, withdrawalsNonce, withdrawalRoot);

        withdrawalsNonce = withdrawalsNonce + 1;

        IRestakedETH(_restakedTokenAddress).burn(msg.sender, withdrawalInfo.amount);

        return withdrawalsNonce - 1;
    }

    function withdrawalDelayBlocks() public view returns (uint32) {
        return uint32(IStrategyManager(_eigenLayerStrategyManagerAddress).withdrawalDelayBlocks());
    }

    function canWithdraw(uint96 withdrawalNonce, uint256 middlewareTimesIndex) external view returns (bool) {
        WithdrawalInfo memory withdrawalInfo = withdrawalsByNonce[msg.sender][withdrawalNonce];
        if (withdrawalInfo.withdrawalStartBlock + withdrawalDelayBlocks() > uint32(block.number)) {
            return false;
        }
        address operator = IDelegationManager(IStrategyManager(_eigenLayerStrategyManagerAddress).delegation()).delegatedTo(address(this));
        return ISlasher(IStrategyManager(_eigenLayerStrategyManagerAddress).slasher()).canWithdraw(operator, withdrawalInfo.withdrawalStartBlock, middlewareTimesIndex);
    }

    function completeQueuedWithdrawal(uint96 withdrawalNonce, uint256 middlewareTimesIndex) public whenNotPaused {
        WithdrawalInfo memory withdrawalInfo = withdrawalsByNonce[msg.sender][withdrawalNonce];

        require(withdrawalInfo.withdrawCompletedAt == 0, "AstridProtocol: Withdrawal already completed");
        require(withdrawalInfo.withdrawer == msg.sender, "AstridProtocol: Invalid withdrawer");

        uint256[] memory strategyIndexesArr = new uint256[](1);
        strategyIndexesArr[0] = 1;
        IStrategy[] memory strategiesArr = new IStrategy[](1);
        strategiesArr[0] = IStrategy(_eigenLayerStrategyStEthAddress);
        uint256[] memory sharesArr = new uint256[](1);
        sharesArr[0] = withdrawalInfo.shares;

        address operator = IDelegationManager(IStrategyManager(_eigenLayerStrategyManagerAddress).delegation()).delegatedTo(address(this));

        IStrategyManager.WithdrawerAndNonce memory withdrawerAndNonce = IStrategyManager.WithdrawerAndNonce({
            withdrawer: address(this),
            nonce: withdrawalNonce
        });

        IStrategyManager.QueuedWithdrawal memory queuedWithdrawal = IStrategyManager.QueuedWithdrawal({
            strategies: strategiesArr,
            shares: sharesArr,
            depositor: address(this),
            withdrawerAndNonce: withdrawerAndNonce,
            withdrawalStartBlock: withdrawalInfo.withdrawalStartBlock,
            delegatedAddress: operator
        });

        IERC20[] memory tokens = new IERC20[](1);
        tokens[0] = IERC20(_stakedTokenAddress);

        uint256 balanceBefore = IERC20(_stakedTokenAddress).balanceOf(address(this));
        IStrategyManager(_eigenLayerStrategyManagerAddress).completeQueuedWithdrawal(
            queuedWithdrawal,
            tokens,
            middlewareTimesIndex,
            true
        );
        uint256 balanceAfter = IERC20(_stakedTokenAddress).balanceOf(address(this));

        for (uint256 i = 0; i < withdrawals[msg.sender].length; i++) {
            if (withdrawals[msg.sender][i].nonce == withdrawalNonce) {
                withdrawals[msg.sender][i].pending = false;
                withdrawals[msg.sender][i].withdrawCompletedAt = block.timestamp;
            }
        }

        withdrawalsByNonce[msg.sender][withdrawalNonce].pending = false;
        withdrawalsByNonce[msg.sender][withdrawalNonce].withdrawCompletedAt = block.timestamp;

        bool sent = _payDirect(msg.sender, balanceAfter.sub(balanceBefore), _stakedTokenAddress);
        require(sent, "AstridProtocol: Failed to send staked token");

        emit WithdrawCompleted(msg.sender, withdrawalInfo.amount, withdrawalInfo.shares, withdrawalInfo.nonce, withdrawalInfo.withdrawalRoot);
    }

}