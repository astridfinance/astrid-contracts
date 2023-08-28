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
import "./interfaces/IDelegator.sol";
import "./eigenlayer/interfaces/IStrategyManager.sol";
import "./eigenlayer/interfaces/IStrategy.sol";
import "./eigenlayer/interfaces/ISlasher.sol";
import "./eigenlayer/interfaces/IDelegationManager.sol";

contract Delegator is IDelegator, Initializable, UUPSUpgradeable, PausableUpgradeable, AccessControlUpgradeable, ReentrancyGuard {

    using SafeMath for uint256;
    using SafeERC20 for IERC20;

    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant UPGRADER_ROLE = keccak256("UPGRADER_ROLE");
    bytes32 public constant ASTRID_ROLE = keccak256("ASTRID_ROLE");

    struct WithdrawalInfo {
        address stakedTokenAddress;
        uint256 amount;
        uint256 shares;
        bool pending;
        uint32 withdrawalStartBlock;
        uint256 withdrawInitiatedAt;
        uint256 withdrawCompletedAt;
        uint256 nonce;
        bytes32 withdrawalRoot;
    }

    address public astridProtocolAddress;
    WithdrawalInfo[] public withdrawals;
    uint96 public withdrawalsNonce;

    event AstridProtocolAddressSet(address oldAddress, address newAddress);
    event RestakePerformed(address stakedTokenAddress, uint256 amount, uint256 shares);
    event WithdrawQueued(address stakedTokenAddress, uint256 amount, uint256 shares, uint256 nonce, bytes32 withdrawalRoot);
    event WithdrawCompleted(uint96 withdrawalIndex);
    event Pull(address indexed to, address token, uint256 value);
    event PullETH(address indexed to, uint256 value);

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address _astridProtocolAddr) initializer public {
        __Pausable_init();
        __AccessControl_init();
        __UUPSUpgradeable_init();

        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);
        _grantRole(UPGRADER_ROLE, msg.sender);

        astridProtocolAddress = _astridProtocolAddr;
        _grantRole(ASTRID_ROLE, astridProtocolAddress);
    }

    function setAstridProtocolAddress(
        address _astridProtocolAddr
    ) public whenNotPaused onlyRole(DEFAULT_ADMIN_ROLE) {
        emit AstridProtocolAddressSet(astridProtocolAddress, _astridProtocolAddr);

        _revokeRole(ASTRID_ROLE, astridProtocolAddress);
        astridProtocolAddress = _astridProtocolAddr;
        _grantRole(ASTRID_ROLE, astridProtocolAddress);
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

    function restake(
        address _stakedTokenAddress,
        address _eigenLayerStrategyManagerAddress,
        address _eigenLayerStrategyAddress
    ) public nonReentrant whenNotPaused onlyRole(ASTRID_ROLE) returns (uint256) {
        uint256 amount = IERC20(_stakedTokenAddress).balanceOf(address(this));

        IERC20(_stakedTokenAddress).approve(_eigenLayerStrategyManagerAddress, amount);
        uint256 shares = IStrategyManager(_eigenLayerStrategyManagerAddress).depositIntoStrategy(
            IStrategy(_eigenLayerStrategyAddress),
            IERC20(_stakedTokenAddress),
            amount
        );

        emit RestakePerformed(_stakedTokenAddress, amount, shares);

        return shares;
    }

    function queueWithdrawal(
        address _stakedTokenAddress,
        address _eigenLayerStrategyManagerAddress,
        address _eigenLayerStrategyAddress
    ) public nonReentrant whenNotPaused onlyRole(ASTRID_ROLE) returns (uint96) {
        uint256 shares = IStrategy(_eigenLayerStrategyAddress).shares(address(this));
        uint256 amount = IStrategy(_eigenLayerStrategyAddress).userUnderlyingView(address(this));

        uint256[] memory strategyIndexesArr = new uint256[](1);
        strategyIndexesArr[0] = 1;
        IStrategy[] memory strategiesArr = new IStrategy[](1);
        strategiesArr[0] = IStrategy(_eigenLayerStrategyAddress);
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
            stakedTokenAddress: _stakedTokenAddress,
            amount: amount,
            shares: shares,
            pending: true,
            withdrawalStartBlock: uint32(block.number),
            withdrawInitiatedAt: block.timestamp,
            withdrawCompletedAt: 0,
            nonce: withdrawalsNonce,
            withdrawalRoot: withdrawalRoot
        });
        withdrawals.push(withdrawalInfo);

        emit WithdrawQueued(_stakedTokenAddress, amount, shares, withdrawalsNonce, withdrawalRoot);

        withdrawalsNonce += 1;

        return withdrawalsNonce - 1;
    }

    function canWithdraw(
        uint96 _withdrawalIndex,
        uint256 _middlewareTimesIndex,
        address _eigenLayerStrategyManagerAddress
    ) external view returns (bool) {
        WithdrawalInfo memory withdrawalInfo = withdrawals[_withdrawalIndex];
        uint32 withdrawalDelayBlocks = uint32(IStrategyManager(_eigenLayerStrategyManagerAddress).withdrawalDelayBlocks());

        if (withdrawalInfo.withdrawalStartBlock + withdrawalDelayBlocks > uint32(block.number)) {
            return false;
        }
        address operator = IDelegationManager(IStrategyManager(_eigenLayerStrategyManagerAddress).delegation()).delegatedTo(address(this));
        return ISlasher(IStrategyManager(_eigenLayerStrategyManagerAddress).slasher()).canWithdraw(operator, withdrawalInfo.withdrawalStartBlock, _middlewareTimesIndex);
    }

    function completeQueuedWithdrawal(
        uint96 _withdrawalIndex,
        uint256 _middlewareTimesIndex,
        address _eigenLayerStrategyManagerAddress,
        address _eigenLayerStrategyAddress
    ) public nonReentrant whenNotPaused onlyRole(ASTRID_ROLE) {
        WithdrawalInfo memory withdrawalInfo = withdrawals[_withdrawalIndex];

        require(withdrawalInfo.withdrawCompletedAt == 0, "AstridProtocol: Withdrawal already completed");

        uint256[] memory strategyIndexesArr = new uint256[](1);
        strategyIndexesArr[0] = 1;
        IStrategy[] memory strategiesArr = new IStrategy[](1);
        strategiesArr[0] = IStrategy(_eigenLayerStrategyAddress);
        uint256[] memory sharesArr = new uint256[](1);
        sharesArr[0] = withdrawalInfo.shares;

        address operator = IDelegationManager(IStrategyManager(_eigenLayerStrategyManagerAddress).delegation()).delegatedTo(address(this));

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
        tokens[0] = IERC20(withdrawalInfo.stakedTokenAddress);

        IStrategyManager(_eigenLayerStrategyManagerAddress).completeQueuedWithdrawal(
            queuedWithdrawal,
            tokens,
            _middlewareTimesIndex,
            true
        );

        withdrawals[_withdrawalIndex].pending = false;
        withdrawals[_withdrawalIndex].withdrawCompletedAt = block.timestamp;

        emit WithdrawCompleted(_withdrawalIndex);
    }

    function pull(address token) public nonReentrant whenNotPaused onlyRole(ASTRID_ROLE) returns (uint256 balance) {
        balance = IERC20(token).balanceOf(address(this));
        bool sent = Utils.payDirect(msg.sender, balance, token);
        require(sent, "AstridProtocol: Failed to send token");
        emit Pull(msg.sender, token, balance);
    }

    function pullETH() public payable nonReentrant whenNotPaused onlyRole(ASTRID_ROLE) returns (uint256 balance) {
        balance = address(this).balance;
        Utils.safeTransferETH(msg.sender, balance);
        emit PullETH(msg.sender, balance);
    }

    function getAssetBalances(
        address _eigenLayerStrategyManagerAddress
    ) external view returns (address[] memory, uint256[] memory) {
        (IStrategy[] memory strategies, ) = IStrategyManager(
            _eigenLayerStrategyManagerAddress
        ).getDeposits(address(this));

        uint256 strategiesLength = strategies.length;
        address[] memory assets = new address[](strategiesLength);
        uint256[] memory assetBalances = new uint256[](strategiesLength);

        for (uint256 i = 0; i < strategiesLength; ) {
            assets[i] = address(IStrategy(strategies[i]).underlyingToken());
            assetBalances[i] = IStrategy(strategies[i]).userUnderlyingView(address(this));
            unchecked {
                ++i;
            }
        }
        return (assets, assetBalances);
    }

    function getAssetBalance(
        address _eigenLayerStrategyAddress
    ) external view returns (uint256) {
        return IStrategy(_eigenLayerStrategyAddress).userUnderlyingView(address(this));
    }

}