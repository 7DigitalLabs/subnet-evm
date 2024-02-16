// SPDX-License-Identifier: MIT 
pragma solidity ^0.8.0;

import "./IAllowList.sol";

interface WhitelistManagerInterface is IAllowList {
    // Set [addr] to have the admin role over the allow list
    function setAdmin(address addr) external;

    function removeAdmin(address addr) external;

    // Set [addr] to be enabled on the allow list
    function setWhitelist(address _contract, bytes calldata _method, bool _status) external;

    // Set [addr] to be enabled on the allow list
    function getWhitelist(address _contract, bytes calldata _method) external;

    // Read the status of [addr]
    function readContractWhitelist(string memory method) external view returns (uint256);
}