// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

import {IAccount} from "../../lib/account-abstraction/contracts/interfaces/IAccount.sol";
import {PackedUserOperation} from "../../lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {Ownable} from "../../lib/openzeppelin-contracts/contracts/access/Ownable.sol";
import {MessageHashUtils} from "../../lib/openzeppelin-contracts/contracts/utils/cryptography/MessageHashUtils.sol";
import {ECDSA} from "../../lib/openzeppelin-contracts/contracts/utils/cryptography/ECDSA.sol";
import {SIG_VALIDATION_FAILED, SIG_VALIDATION_SUCCESS} from "../../lib/account-abstraction/contracts/core/Helpers.sol";
import {IEntryPoint} from "../../lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";

/**
 * @title MinimalAccount
 * @dev A minimal implementation of an Account contract that integrates with
 * an EntryPoint contract for account abstraction.
 * The contract inherits OpenZeppelin's Ownable for ownership management.
 */
contract MinimalAccount is IAccount, Ownable {
    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/
    error MinimalAccount__MissingFundsNotPositive();
    error MinimalAccount__NotFromEntryPoint();
    error MinimalAccount__NotFromEntryPointOrOwner();
    error MinimalAccount__TransferFailed();

    /*//////////////////////////////////////////////////////////////
                            STATE VARIABLES
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev The EntryPoint contract instance that this account is associated with.
     * This is immutable and set during contract deployment.
     */
    IEntryPoint private immutable i_entryPoint;

    /*//////////////////////////////////////////////////////////////
                                MODIFIERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Modifier to ensure the function is only called by the EntryPoint contract.
     */
    modifier requireFromEntryPoint() {
        if (msg.sender != address(i_entryPoint)) {
            revert MinimalAccount__NotFromEntryPoint();
        }
        _;
    }

    /**
     * @dev Modifier to ensure the function is only called by the EntryPoint contract or the contract owner.
     */
    modifier requireFromEntryPointOrOwner() {
        if (msg.sender != address(i_entryPoint) && msg.sender != owner()) {
            revert MinimalAccount__NotFromEntryPointOrOwner();
        }
        _;
    }

    /*//////////////////////////////////////////////////////////////
                                FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Constructor to initialize the MinimalAccount contract.
     * @param entryPoint The address of the EntryPoint contract.
     */
    constructor(address entryPoint) Ownable(msg.sender) {
        i_entryPoint = IEntryPoint(entryPoint);
    }

    /**
     * @dev Fallback function to receive Ether.
     * This function is called when the contract receives Ether with empty calldata.
     */
    receive() external payable {}

    /**
     * @dev Fallback function to receive Ether.
     * This function is called when the contract receives Ether with non-empty calldata.
     */
    fallback() external payable {}

    /*//////////////////////////////////////////////////////////////
                        EXTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Executes a transaction from the account to a target address.
     * @param dest The address to which the call is made.
     * @param value The amount of Ether to send.
     * @param functionData The call data to be sent.
     */
    function execute(
        address dest,
        uint256 value,
        bytes calldata functionData
    ) external requireFromEntryPointOrOwner {
        (bool success, ) = dest.call{value: value}(functionData);
        if (!success) {
            revert MinimalAccount__TransferFailed();
        }
    }

    /**
     * @dev Validates a user operation before execution.
     * @param userOp The packed user operation data.
     * @param userOpHash The hash of the user operation.
     * @param missingAccountFunds The amount of funds required to complete the operation.
     * @return validationData The result of the signature validation.
     */
    function validateUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external requireFromEntryPoint returns (uint256 validationData) {
        validationData = _validateSignature(userOp, userOpHash);
        _payPrefund(missingAccountFunds);
    }

    /*//////////////////////////////////////////////////////////////
                        INTERNAL FUNCTIONS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Internal function to validate the signature of a user operation.
     * Uses EIP-191 to recover the signer address.
     * @param userOp The packed user operation data.
     * @param userOpHash The hash of the user operation.
     * @return validationData A status code indicating the result of the signature validation.
     */
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view returns (uint256 validationData) {
        bytes32 ethSignedMessageHash = MessageHashUtils.toEthSignedMessageHash(
            userOpHash
        );
        address signer = ECDSA.recover(ethSignedMessageHash, userOp.signature);
        if (signer != owner()) {
            return SIG_VALIDATION_FAILED;
        }
        return SIG_VALIDATION_SUCCESS;
    }

    /**
     * @dev Internal function to pay the required funds for the operation.
     * @param missingAccountFunds The amount of funds needed to be transferred.
     */
    function _payPrefund(uint256 missingAccountFunds) internal {
        // Check if the missingAccountFunds is positive, otherwise throw the custom error
        if (missingAccountFunds <= 0) {
            revert MinimalAccount__MissingFundsNotPositive();
        }

        // Attempt to transfer the funds to msg.sender
        (bool success, ) = payable(msg.sender).call{value: missingAccountFunds}(
            ""
        );

        // Check if the transfer was successful, otherwise throw the custom error
        if (!success) {
            revert MinimalAccount__TransferFailed();
        }
    }

    /*//////////////////////////////////////////////////////////////
                            GETTERS
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev Returns the address of the EntryPoint contract associated with this account.
     * @return The address of the EntryPoint contract.
     */
    function getEntryPoint() external view returns (address) {
        return address(i_entryPoint);
    }
}
