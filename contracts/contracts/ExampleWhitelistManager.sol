// (c) 2022-2023, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// SPDX-License-Identifier: MIT

pragma solidity >=0.8.0;

import "./interfaces/IWhitelistManager.sol";



contract WhitelistManager {

    address constant WHITELIST_ADDRESS = 0x0300000000000000000000000000000000000000;

    WhitelistManagerInterface a = WhitelistManagerInterface(WHITELIST_ADDRESS);
    

    
}