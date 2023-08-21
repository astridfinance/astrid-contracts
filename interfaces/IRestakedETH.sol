// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

interface IRestakedETH {

    function mint(address to, uint256 amount) external;

    function burn(address from, uint256 amount) external;

    function totalSupply() external view returns (uint256);

}