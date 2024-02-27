// (c) 2019-2020, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package whitelistmanager

import (
	_ "embed"
	"errors"
	"fmt"

	"github.com/ava-labs/subnet-evm/precompile/allowlist"
	"github.com/ava-labs/subnet-evm/precompile/contract"
	"github.com/ava-labs/subnet-evm/vmerrs"
	"github.com/ethereum/go-ethereum/common"
)

const (
	ModifyWhitelistGasCost = contract.WriteGasCostPerSlot
	ReadWhitelistGasCost   = contract.ReadGasCostPerSlot

	WhitelistInputLen = 5 * common.HashLength
)

var (
	NotWhitelisted = Whitelist(common.BigToHash(common.Big0))
	Whitelisted    = Whitelist(common.BigToHash(common.Big1))
	// Singleton StatefulPrecompiledContract for minting native assets by permissioned callers.

	ErrCannotWhitelisted = errors.New("non-enabled cannot edit whitelist")
)

var (
	// WhitelistManagerRawABI contains the raw ABI of Warp contract.
	//go:embed contract.abi
	WhitelistManagerRawABI string

	WhitelistManagerABI = contract.ParseABI(WhitelistManagerRawABI)

	WhitelistManagerPrecompile = createWhitelistManagerPrecompile()
)

type Whitelist common.Hash

// IsEnabled returns true if [r] indicates that it has permission to access the resource.
func (w Whitelist) IsWhitelisted() bool {
	switch w {
	case Whitelisted:
		return true
	default:
		return false
	}
}

// GetWhiteListManagerStatus returns the role of [address] for the fee config manager list.
func GetWhitelistManagerStatus(stateDB contract.StateDB, address common.Address) allowlist.Role {
	return allowlist.GetAllowListStatus(stateDB, ContractAddress, address)
}

// SetWhiteListManagerStatus sets the permissions of [address] to [role] for the
// fee config manager list. assumes [role] has already been verified as valid.
func SetWhitelistManagerStatus(stateDB contract.StateDB, address common.Address, role allowlist.Role) {
	allowlist.SetAllowListRole(stateDB, ContractAddress, address, role)
}

// GetWhiteListStatus returns the status of [address] for the whitelist.
func GetWhitelistStatus(stateDB contract.StateDB, address common.Address, method []byte) Whitelist {
	hash := common.BytesToHash(append(address[:], method[:8]...))
	//addressKey := address.Hash()

	return Whitelist(stateDB.GetState(ContractAddress, hash))
}

// SetWhitelistStatus sets the permissions of [address][hash] to [status] for the
// assumes [status] has already been verified as valid.
func SetWhitelistStatus(stateDB contract.StateDB, address common.Address, method []byte, status Whitelist) {
	// Generate the state key for [address]
	hash := common.BytesToHash(append(address[:], method[:8]...))
	//addressKey := address.Hash()
	// Assign [status] to the address
	// This stores the [status] in the contract storage with address [ContractAddress]
	// and [addressKey] hash. It means that any reusage of the [addressKey] for different value
	// conflicts with the same slot [status] is stored.
	// Precompile implementations must use a different key than [addressKey]
	stateDB.SetState(ContractAddress, hash, common.Hash(status))
}

// UnpackWhitelist attempts to unpack [input] into the arguments to the mint precompile
// assumes that [input] does not include selector (omits first 4 bytes in PackMintInput)
func UnpackWhitelist(input []byte) (common.Address, []byte, bool, error) {
	if len(input) != WhitelistInputLen {
		return common.Address{}, []byte{}, false, fmt.Errorf("invalid input length: %d", len(input))
	}
	to := common.BytesToAddress(contract.PackedHash(input, 0))
	method := contract.PackedHash(input, 4)
	status := int(contract.PackedHash(input, 2)[31])

	if status == 0 {
		return to, method, false, nil
	}

	return to, method, true, nil
}

// setFeeConfig checks if the caller has permissions to set the fee config.
// The execution function parses [input] into FeeConfig structure and sets contract storage accordingly.
func setWhitelistStatus(accessibleState contract.AccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	if remainingGas, err = contract.DeductGas(suppliedGas, ModifyWhitelistGasCost); err != nil {
		return nil, 0, err
	}

	if len(input) != WhitelistInputLen {
		return nil, remainingGas, fmt.Errorf("invalid input length for modifying whitelist: %d", len(input))
	}

	

	modifyAddress, method, status, err := UnpackWhitelist(input)


	if err != nil {
		return nil, remainingGas, err
	}

	if readOnly {
		return nil, remainingGas, vmerrs.ErrWriteProtection
	}

	stateDB := accessibleState.GetStateDB()

	callerStatus := GetWhitelistManagerStatus(stateDB, caller)
	if !callerStatus.IsEnabled() {
		return nil, remainingGas, fmt.Errorf("%w: %s", ErrCannotWhitelisted, caller)
	}
	if status {
		SetWhitelistStatus(stateDB, modifyAddress, method, Whitelisted)
	} else {
		SetWhitelistStatus(stateDB, modifyAddress, method, NotWhitelisted)
	}

	// Return an empty output and the remaining gas
	return []byte{}, remainingGas, nil
}

// getFeeConfig returns the stored fee config as an output.
// The execution function reads the contract state for the stored fee config and returns the output.
func getWhitelistStatus(accessibleState contract.AccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	if remainingGas, err = contract.DeductGas(suppliedGas, ReadWhitelistGasCost); err != nil {
		return nil, 0, err
	}


	method := contract.PackedHash(input, 3)

	readAddress := common.BytesToAddress(contract.PackedHash(input, 0))

	whitelist := GetWhitelistStatus(accessibleState.GetStateDB(), readAddress, method)
	whitelistResult := common.Hash(whitelist).Bytes()

	// Return the fee config as output and the remaining gas
	return whitelistResult, remainingGas, err
}

// createWhitelistManagerPrecompile returns a StatefulPrecompiledContract with getters and setters for the precompile.
// Access to the getters/setters is controlled by an allow list for ContractAddress.
func createWhitelistManagerPrecompile() contract.StatefulPrecompiledContract {
	var functions []*contract.StatefulPrecompileFunction
	functions = append(functions, allowlist.CreateAllowListFunctions(ContractAddress)...)

	abiFunctionMap := map[string]contract.RunStatefulPrecompileFunc{
		"setWhitelist": setWhitelistStatus,
		"getWhitelist": getWhitelistStatus,
	}

	for name, function := range abiFunctionMap {
		method, ok := WhitelistManagerABI.Methods[name]
		if !ok {
			panic(fmt.Errorf("given method (%s) does not exist in the ABI", name))
		}
		functions = append(functions, contract.NewStatefulPrecompileFunction(method.ID, function))
	}
	// Construct the contract with no fallback function.
	statefulContract, err := contract.NewStatefulPrecompileContract(nil, functions)
	if err != nil {
		panic(err)
	}
	return statefulContract
}
