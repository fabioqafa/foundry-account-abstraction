// SPDX-License-Identifier: MIT

pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {ZkMinimalAccount, Transaction, MemoryTransactionHelper, BOOTLOADER_FORMAL_ADDRESS, ACCOUNT_VALIDATION_SUCCESS_MAGIC} from "../../src/zksync/ZkMinimalAccount.sol";
import {ERC20Mock} from "../../lib/openzeppelin-contracts/contracts/mocks/token/ERC20Mock.sol";

contract ZkMinimalAccounTest is Test {
    ZkMinimalAccount minimalAccount;
    ERC20Mock usdc;

    uint256 constant AMOUNT = 1 ether;
    bytes32 constant EMPTY_BYTES_32 = bytes32(0);
    address constant ANVIL_DEFAULT_ACCOUNT =
        0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266;

    function setUp() external {
        minimalAccount = new ZkMinimalAccount();
        usdc = new ERC20Mock();
        minimalAccount.transferOwnership(ANVIL_DEFAULT_ACCOUNT);
        vm.deal(address(minimalAccount), AMOUNT * 10);
    }

    /*
     *  @notice Surprisingly, when function was named `testCommandExecutedByOwner` it failed...
     */
    function testZkOwnerCanExecute() public {
        // Arrange
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory functionData = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        );

        Transaction memory transaction = _createUnsignedTransaction(
            minimalAccount.owner(),
            113,
            dest,
            value,
            functionData
        );
        // // Act
        vm.prank(minimalAccount.owner());

        minimalAccount.executeTransaction(
            EMPTY_BYTES_32,
            EMPTY_BYTES_32,
            transaction
        );
        // // Assert
        assertEq(usdc.balanceOf(address(minimalAccount)), AMOUNT);
    }

    function testBootloaderCanValidate() public {
        // Arrange
        address dest = address(usdc);
        uint256 value = 0;
        bytes memory functionData = abi.encodeWithSelector(
            ERC20Mock.mint.selector,
            address(minimalAccount),
            AMOUNT
        );

        Transaction memory transaction = _createUnsignedTransaction(
            minimalAccount.owner(),
            113,
            dest,
            value,
            functionData
        );

        transaction = _signTransaction(transaction);
        // Act
        vm.prank(BOOTLOADER_FORMAL_ADDRESS);
        bytes4 magic = minimalAccount.validateTransaction(
            EMPTY_BYTES_32,
            EMPTY_BYTES_32,
            transaction
        );
        // Assert
        assertEq(magic, ACCOUNT_VALIDATION_SUCCESS_MAGIC);
    }

    /*////////////////////////////////////////////////////
                            HELPERS
    ////////////////////////////////////////////////////*/
    function _createUnsignedTransaction(
        address from,
        uint8 txnType,
        address to,
        uint256 value,
        bytes memory data
    ) internal view returns (Transaction memory) {
        uint256 nonce = vm.getNonce(address(minimalAccount));
        bytes32[] memory factoryDeps = new bytes32[](0);

        return
            Transaction({
                txType: txnType, // type 113 (0x71).
                from: uint256(uint160(from)),
                to: uint256(uint160(to)),
                gasLimit: 16777216,
                gasPerPubdataByteLimit: 16777216,
                maxFeePerGas: 16777216,
                maxPriorityFeePerGas: 16777216,
                paymaster: 0,
                nonce: nonce,
                value: value,
                reserved: [uint256(0), uint256(0), uint256(0), uint256(0)],
                data: data,
                signature: hex"",
                factoryDeps: factoryDeps,
                paymasterInput: hex"",
                reservedDynamic: hex""
            });
    }

    function _signTransaction(
        Transaction memory transaction
    ) internal view returns (Transaction memory) {
        bytes32 unsignedTxnHash = MemoryTransactionHelper.encodeHash(
            transaction
        );
        uint8 v;
        bytes32 r;
        bytes32 s;
        uint256 ANVIL_DEFAULT_PRIVATE_KEY = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;
        (v, r, s) = vm.sign(ANVIL_DEFAULT_PRIVATE_KEY, unsignedTxnHash);
        Transaction memory signedTransaction = transaction;
        signedTransaction.signature = abi.encodePacked(r, s, v);

        return signedTransaction;
    }
}
