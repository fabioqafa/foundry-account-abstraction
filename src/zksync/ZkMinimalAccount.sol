// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

// zkSync-Era Imports
import {IAccount, ACCOUNT_VALIDATION_SUCCESS_MAGIC} from "../../lib/foundry-era-contracts/src/system-contracts/contracts/interfaces/IAccount.sol";
import {Transaction, MemoryTransactionHelper} from "../../lib/foundry-era-contracts/src/system-contracts/contracts/libraries/MemoryTransactionHelper.sol";
import {SystemContractsCaller} from "../../lib/foundry-era-contracts/src/system-contracts/contracts/libraries/SystemContractsCaller.sol";
import {NONCE_HOLDER_SYSTEM_CONTRACT, BOOTLOADER_FORMAL_ADDRESS, DEPLOYER_SYSTEM_CONTRACT} from "../../lib/foundry-era-contracts/src/system-contracts/contracts/Constants.sol";
import {INonceHolder} from "../../lib/foundry-era-contracts/src/system-contracts/contracts/interfaces/INonceHolder.sol";
import {Utils} from "../../lib/foundry-era-contracts/src/system-contracts/contracts/libraries/Utils.sol";

// Open-Zeppelin Imports
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

contract ZkMinimalAccount is IAccount, Ownable {
    /*//////////////////////////////////////////////////////////////
                                TYPES
    //////////////////////////////////////////////////////////////*/
    using MemoryTransactionHelper for Transaction;

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/
    error ZkMinimalAccount__NotEnoughBalance();
    error ZkMinimalAccount__NotFromBootloader();
    error ZkMinimalAccount__NotFromBootloaderOrOwner();
    error ZkMinimalAccount__ExecutionFailed();
    error ZkMinimalAccount__FailedToPay();
    error ZkMinimalAccount__InvalidSignature();
    
    /*//////////////////////////////////////////////////////////////
                                MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier requireFromBootloader() {
        if (msg.sender != BOOTLOADER_FORMAL_ADDRESS) {
            revert ZkMinimalAccount__NotFromBootloader();
        }
        _;
    }

    modifier requireFromBootloaderOrOwner() {
        if (msg.sender != BOOTLOADER_FORMAL_ADDRESS && msg.sender != owner()) {
            revert ZkMinimalAccount__NotFromBootloaderOrOwner();
        }
        _;
    }

    constructor() Ownable(msg.sender) {}

    receive() external payable {}

    /*//////////////////////////////////////////////////////////////
                           EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    /**
     * @notice Must increase the nonce
     * @notice Must validate the transaction (check the owner signed the transaction)
     * @notice Also check to see if this account has enough money (we will not be using a paymaster)
     * @param _transaction ff
     */
    function validateTransaction(
        bytes32 /*_txHash*/,
        bytes32 /*_suggestedSignedHash*/,
        Transaction memory _transaction
    ) external payable requireFromBootloader returns (bytes4 magic) {
        return _validateTransaction(_transaction);
    }

    /**
     * @notice Executes a transaction with the given parameters. The transaction can either be a system contract call
     * or a regular contract call, depending on the target address (`to`).
     *
     * @param _transaction The `Transaction` struct containing details of the transaction, including the recipient address, value, and data.
     *
     * @dev The function can only be called by the bootloader or the contract owner, as enforced by the `requireFromBootloaderOrOwner` modifier.
     *
     * The transaction execution flow is as follows:
     *  - If the target address (`to`) is the `DEPLOYER_SYSTEM_CONTRACT`, the function calls `systemCallWithPropagatedRevert` from
     *    the `SystemContractsCaller` contract, passing along the gas, value, and data. This is used for executing system-level transactions on zkSync (a.k.a system call simulation).
     *  - If the target address is not the `DEPLOYER_SYSTEM_CONTRACT`, the function performs a low-level call using inline assembly.
     *    This call forwards all remaining gas and attempts to execute the transaction with the specified value and data.
     *  - If the low-level call fails (indicated by the `success` flag), the transaction reverts with a custom error `ZkMinimalAccount__ExecutionFailed`.
     */
    function executeTransaction(
        bytes32 /*_txHash*/,
        bytes32 /*_suggestedSignedHash*/,
        Transaction memory _transaction
    ) external payable requireFromBootloaderOrOwner {
        _executeTransaction(_transaction);
    }

    // There is no point in providing possible signed hash in the `executeTransactionFromOutside` method,
    // since it typically should not be trusted.
    // Here, first we have to validate the transaction, then execute it
    function executeTransactionFromOutside(
        Transaction memory _transaction
    ) external payable {
        bytes4 magic = _validateTransaction(_transaction);
        if (magic != ACCOUNT_VALIDATION_SUCCESS_MAGIC) {
            revert ZkMinimalAccount__InvalidSignature();
        }
        _executeTransaction(_transaction);
    }

    function payForTransaction(
        bytes32 /*_txHash*/,
        bytes32,
        /*_suggestedSignedHash*/
        Transaction memory _transaction
    ) external payable {
        bool success = _transaction.payToTheBootloader();
        if (!success) {
            revert ZkMinimalAccount__FailedToPay();
        }
    }

    function prepareForPaymaster(
        bytes32 _txHash,
        bytes32 _possibleSignedHash,
        Transaction memory _transaction
    ) external payable {}

    /*//////////////////////////////////////////////////////////////
                           INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/
    /**
     * @notice Must increase the nonce
     * @notice Must validate the transaction (check the owner signed the transaction)
     * @notice Also check to see if this account has enough money (we will not be using a paymaster)
     * @param _transaction ff
     */
    function _validateTransaction(
        Transaction memory _transaction
    ) internal returns (bytes4 magic) {
        // 1. Increment the nonce by one (calling the system's contract: NonceHolder.sol)
        // Since it is difficult to directly call system contracts, we do a system call simulation
        SystemContractsCaller.systemCallWithPropagatedRevert(
            uint32(gasleft()),
            address(NONCE_HOLDER_SYSTEM_CONTRACT),
            0,
            abi.encodeCall(
                INonceHolder.incrementMinNonceIfEquals,
                (_transaction.nonce)
            )
        );

        // Check for fee to pay
        uint256 totalRequiredBalance = _transaction.totalRequiredBalance();
        if (totalRequiredBalance > address(this).balance) {
            revert ZkMinimalAccount__NotEnoughBalance();
        }

        // Check for signature
        bytes32 txHash = _transaction.encodeHash();
        address signer = ECDSA.recover(txHash, _transaction.signature);
        bool isValidSigner = signer == owner();

        if (isValidSigner) {
            magic = ACCOUNT_VALIDATION_SUCCESS_MAGIC;
        } else {
            magic = bytes4(0);
        }

        // Return the magic number
        return magic;
    }

    function _executeTransaction(Transaction memory _transaction) internal {
        // Convert the `to` field of the transaction from `uint256` to `address` by casting to `uint160`.
        address to = address(uint160(_transaction.to));

        // Safely cast the `value` field of the transaction to a `uint128`, ensuring that the value fits within this smaller type.
        uint128 value = Utils.safeCastToU128(_transaction.value);

        // Extract the data payload from the transaction.
        bytes memory data = _transaction.data;

        // Check if the transaction is targeting the `DEPLOYER_SYSTEM_CONTRACT`.
        if (to == address(DEPLOYER_SYSTEM_CONTRACT)) {
            // Safely cast the remaining gas to `uint32` and make a system call with propagated revert behavior.
            uint32 gas = Utils.safeCastToU32(gasleft());
            SystemContractsCaller.systemCallWithPropagatedRevert(
                gas,
                to,
                value,
                data
            );
        } else {
            // Execute a low-level call if the target is not the `DEPLOYER_SYSTEM_CONTRACT`.
            bool success;
            assembly {
                // Perform the low-level call with the specified gas, to address, value, and data.
                success := call(
                    gas(),
                    to,
                    value,
                    add(data, 0x20),
                    mload(data),
                    0,
                    0
                )
            }

            // If the call fails, revert the transaction with a custom error.
            if (!success) {
                revert ZkMinimalAccount__ExecutionFailed();
            }
        }
    }
}
