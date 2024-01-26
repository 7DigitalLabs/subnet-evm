// (c) 2019-2020, Ava Labs, Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package whitelistmanager

import (
	_ "encoding/binary"
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

	WhitelistInputLen = common.HashLength + common.HashLength
)

var (
	NotWhitelisted = Whitelist(common.BigToHash(common.Big0))
	Whitelisted    = Whitelist(common.BigToHash(common.Big1))
	// Singleton StatefulPrecompiledContract for minting native assets by permissioned callers.
	WhitelistPrecompile contract.StatefulPrecompiledContract = CreateAllowListPrecompile(ContractAddress)

	setWhitelistSignature = contract.CalculateFunctionSelector("setWhitelist(address,bool)") // address, bool
	getWhitelistSignature = contract.CalculateFunctionSelector("getWhitelist(address)")

	ErrCannotWhitelisted = errors.New("non-enabled cannot mint")
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

// GetFeeManagerStatus returns the role of [address] for the fee config manager list.
func GetWhitelistManagerStatus(stateDB contract.StateDB, address common.Address) allowlist.Role {
	return allowlist.GetAllowListStatus(stateDB, ContractAddress, address)
}

// SetFeeManagerStatus sets the permissions of [address] to [role] for the
// fee config manager list. assumes [role] has already been verified as valid.
func SetWhitelistManagerStatus(stateDB contract.StateDB, address common.Address, role allowlist.Role) {
	allowlist.SetAllowListRole(stateDB, ContractAddress, address, role)
}

// GetTxAllowListStatus returns the status of [address] for the whitelist.
func GetWhitelistStatus(stateDB contract.StateDB, address common.Address) Whitelist {
	g := common.BytesToHash(append(address[:], address[:]...))
	//addressKey := address.Hash()

	return Whitelist(stateDB.GetState(ContractAddress, g))
}

// SetWhitelistStatus sets the permissions of [address] to [status] for the
// tx allow list.
// assumes [status] has already been verified as valid.
func SetWhitelistStatus(stateDB contract.StateDB, address common.Address, status Whitelist) {
	// Generate the state key for [address]
	g := common.BytesToHash(append(address[:], address[:]...))
	//addressKey := address.Hash()
	// Assign [status] to the address
	// This stores the [status] in the contract storage with address [ContractAddress]
	// and [addressKey] hash. It means that any reusage of the [addressKey] for different value
	// conflicts with the same slot [status] is stored.
	// Precompile implementations must use a different key than [addressKey]
	stateDB.SetState(ContractAddress, g, common.Hash(status))
}

/*
// createAllowListRoleSetter returns an execution function for setting the allow list status of the input address argument to [role].
// This execution function is speciifc to [precompileAddr].
func createWhitelistSetter(precompileAddr common.Address, status Whitelist) contract.RunStatefulPrecompileFunc {
	return func(evm contract.AccessibleState, callerAddr, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) (ret []byte, remainingGas uint64, err error) {
		if remainingGas, err = contract.DeductGas(suppliedGas, ModifyAllowListGasCost); err != nil {
			return nil, 0, err
		}

		if len(input) != allowListInputLen {
			return nil, remainingGas, fmt.Errorf("invalid input length for modifying allow list: %d", len(input))
		}

		modifyAddress := common.BytesToAddress(input)

		if readOnly {
			return nil, remainingGas, vmerrs.ErrWriteProtection
		}

		stateDB := evm.GetStateDB()

		callerStatus := GetWhitelistManagerStatus(stateDB, callerAddr)
		if !callerStatus.IsAdmin() {
			return nil, remainingGas, fmt.Errorf("%w: modify address: %s, from role: %s, to role: %s", ErrCannotWhitelisted, callerAddr, callerStatus, allowlist.AdminRole)
		}
		SetWhitelistStatus(stateDB, modifyAddress, status)
		// Return an empty output and the remaining gas
		return []byte{}, remainingGas, nil
	}
}

// createReadAllowList returns an execution function that reads the allow list for the given [precompileAddr].
// The execution function parses the input into a single address and returns the 32 byte hash that specifies the
// designated role of that address
func createReadAllowList(precompileAddr common.Address) contract.RunStatefulPrecompileFunc {
	return func(evm contract.AccessibleState, callerAddr common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) (ret []byte, remainingGas uint64, err error) {
		if remainingGas, err = contract.DeductGas(suppliedGas, ReadAllowListGasCost); err != nil {
			return nil, 0, err
		}

		if len(input) != allowListInputLen {
			return nil, remainingGas, fmt.Errorf("invalid input length for read allow list: %d", len(input))
		}

		readAddress := common.BytesToAddress(input)
		whitelist := GetWhitelistStatus(evm.GetStateDB(), readAddress)
		whitelistBytes := common.Hash(whitelist).Bytes()
		return whitelistBytes, remainingGas, nil
	}
}*/

func CreateAllowListPrecompile(precompileAddr common.Address) contract.StatefulPrecompiledContract {
	// Construct the contract with no fallback function.
	allowListFuncs := CreateAllowListFunctions(precompileAddr)
	contract, err := contract.NewStatefulPrecompileContract(nil, allowListFuncs)
	// TODO Change this to be returned as an error after refactoring this precompile
	// to use the new precompile template.
	if err != nil {
		panic(err)
	}
	return contract
}

// UnpackWhitelist attempts to unpack [input] into the arguments to the mint precompile
// assumes that [input] does not include selector (omits first 4 bytes in PackMintInput)
func UnpackWhitelist(input []byte) (common.Address, bool, error) {
	if len(input) != WhitelistInputLen {
		return common.Address{}, false, fmt.Errorf("invalid input length: %d", len(input))
	}
	to := common.BytesToAddress(contract.PackedHash(input, 0))
	data := int(contract.PackedHash(input, 1)[31])

	if data == 0 {
		return to, false, nil
	}

	return to, true, nil
}

// setFeeConfig checks if the caller has permissions to set the fee config.
// The execution function parses [input] into FeeConfig structure and sets contract storage accordingly.
func setWhitelistStatus(accessibleState contract.AccessibleState, caller common.Address, addr common.Address, input []byte, suppliedGas uint64, readOnly bool) (ret []byte, remainingGas uint64, err error) {
	if remainingGas, err = contract.DeductGas(suppliedGas, ModifyWhitelistGasCost); err != nil {
		return nil, 0, err
	}

	if len(input) != WhitelistInputLen {
		return nil, remainingGas, fmt.Errorf("invalid input length for modifying allow list: %d", len(input))
	}

	modifyAddress, status, err := UnpackWhitelist(input)
	if err != nil {
		return nil, remainingGas, err
	}

	if readOnly {
		return nil, remainingGas, vmerrs.ErrWriteProtection
	}

	stateDB := accessibleState.GetStateDB()
	// Verify that the caller is in the allow list and therefore has the right to call this function.
	callerStatus := GetWhitelistManagerStatus(stateDB, caller)
	if !callerStatus.IsEnabled() {
		return nil, remainingGas, fmt.Errorf("%w: %s", ErrCannotWhitelisted, caller)
	}
	if status {
		SetWhitelistStatus(stateDB, modifyAddress, Whitelisted)
	} else {
		SetWhitelistStatus(stateDB, modifyAddress, NotWhitelisted)
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

	readAddress := common.BytesToAddress(input)
	whitelist := GetWhitelistStatus(accessibleState.GetStateDB(), readAddress)
	whitelistBytes := common.Hash(whitelist).Bytes()

	// Return the fee config as output and the remaining gas
	return whitelistBytes, remainingGas, err
}

func CreateAllowListFunctions(precompileAddr common.Address) []*contract.StatefulPrecompileFunction {
	setWhitelistFunc := contract.NewStatefulPrecompileFunction(setWhitelistSignature, setWhitelistStatus)
	getWhitelistFunc := contract.NewStatefulPrecompileFunction(getWhitelistSignature, getWhitelistStatus)

	return []*contract.StatefulPrecompileFunction{setWhitelistFunc, getWhitelistFunc}
}
