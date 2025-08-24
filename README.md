![si_header](img/si_header.png)

[![riccardomalatesta.eth](https://img.shields.io/badge/ENS-riccardomalatesta.eth-blue)](https://app.ens.domains/riccardomalatesta.eth)
[![License](https://img.shields.io/github/license/seeu-inspace/solidityinspector)](LICENSE)
[![Open Source Love](https://badges.frapsoft.com/os/v1/open-source.svg?v=103)](https://github.com/ellerbrock/open-source-badges/)

SolidityInspector is a Ruby-based static analyzer built to enhance the security, efficiency, and reliability of Solidity smart contracts. Designed for developers, auditors, and security researchers, it systematically detects gas inefficiencies, security risks, and code quality issues, covering 23 Gas optimizations, 24 Non-Critical findings, 28 Low, 12 Medium, and 13 High-severity vulnerabilities.

By running SolidityInspector on your codebase, you gain actionable insights that help prevent exploits, minimize gas costs, and streamline audits. The tool generates a comprehensive Markdown report, making it easy to review findings and integrate fixes into your workflow.

My inspirations for creating this tool were [c4udit](https://github.com/byterocket/c4udit), [4analy3er](https://github.com/Picodes/4naly3er), [Aderyn](https://github.com/Cyfrin/aderyn) and [Slither](https://github.com/crytic/slither).

## Usage

#### Linux
1. Ensure that you have Ruby installed on your system and Run the following command to install SolidityInspector
  ```shell
  bash <(curl -sL https://raw.githubusercontent.com/seeu-inspace/solidityinspector/main/install.sh)
  ```
2. Run the command `solidityinspector`
3. Enter the path to the directory containing the smart contracts to analyze

#### Alternatively
1. Download [solidityinspector.rb](https://github.com/seeu-inspace/solidityinspector/blob/main/solidityinspector.rb) and Ensure that you have Ruby installed on your system;
2. Run the Script with `ruby solidityinspector.rb`
3. Enter the path to the directory containing the smart contracts to analyze. Ideally, save the directory containing the contracts in the same directory as the script


### Example of usage

```shell
┌──(kali㉿kali)-[~/Documents/KittensOnChain]
└─$ solidityinspector
 __                     ___       _
(_  _  |  o  _| o _|_ \/ | __  _ |_) _  _ _|_ _  __
__)(_) |  | (_| |  |_ / _|_| |_> |  (/_(_  |_(_) |
└───────■ Made with <3 by Riccardo Malatesta (@seeu)

Subdirectories in the current directory:
├─ script
├─ img
├─ src
├─ .git
├─ cache
├─ broadcast
├─ test
└─ .github

┌─ Enter a directory:
└─ src
┌─ Enter the path of the out-of-scope file [leave blank if not needed]:
└─ out_of_scope.txt

Files analyzed:
└─ src/KittensOnChain.sol


Use assembly to check for address(0) Instances (1) 
src/KittensOnChain.sol
::105 =>         if (ownerOf(tokenId) == address(0)) {

require()/revert() statements should have descriptive reason strings Instances (1) 
src/KittensOnChain.sol
::51 =>         require(

Unnamed return parameters Instances (6) 
src/KittensOnChain.sol
::143 =>     function getStateOfToken(uint256 tokenId) public view returns (ColorTrait) {
::150 =>     function getYellowKitten() public view returns (string memory) {
::157 =>     function getRedKitten() public view returns (string memory) {
::164 =>     function getBlueKitten() public view returns (string memory) {
::171 =>     function getGreenKitten() public view returns (string memory) {
::178 =>     function getTokenCounter() public view returns (uint256) {

Usage of abi.encodePacked instead of bytes.concat() for Solidity version >= 0.8.4 Instances (2) 
src/KittensOnChain.sol
::121 =>                 abi.encodePacked(
::124 =>                         abi.encodePacked(

public function not used internally could be marked as external Instances (8) 
src/KittensOnChain.sol
::68 =>     function mintNft() public {
::79 =>     function changeColor(uint256 tokenId) public {
::143 =>     function getStateOfToken(uint256 tokenId) public view returns (ColorTrait) {
::150 =>     function getYellowKitten() public view returns (string memory) {
::157 =>     function getRedKitten() public view returns (string memory) {
::164 =>     function getBlueKitten() public view returns (string memory) {
::171 =>     function getGreenKitten() public view returns (string memory) {
::178 =>     function getTokenCounter() public view returns (uint256) {

Compiler version Pragma is non-specific Instances (1) 
src/KittensOnChain.sol => pragma solidity ^0.8.18;

Timestamp dependency: use of block.timestamp (or now) Instances (1) 
src/KittensOnChain.sol
::129 =>                             Strings.toString(uint256(block.timestamp) % 100),

Centralization risk detected: contract has a single point of control Instances (2) 
src/KittensOnChain.sol
::14 => contract KittensOnChain is ERC721, Ownable {
::50 =>     ) ERC721("Kitten", "KTN") Ownable(msg.sender) {

Report generated: solidityinspector_report.md
Analysis executed in 0.005374072 seconds
```


## Example reports

These are results obtained during contests using SolidityInspector.

| Project | Platform | Date | Report | Type | Result |
| :-----: | :------: | :--: | :----: | :--: | :----: |
| Wenwin | Code4rena | 09 - 03 -2023 | [📄](https://github.com/code-423n4/2023-03-wenwin-findings/issues/485) | QA Report | B grade |
| Ethos Reserve | Code4rena | 07 - 03 -2023 | [📄](https://github.com/code-423n4/2023-02-ethos-findings/issues/31) | Gas Report | B grade |
| Popcorn | Code4rena | 07 - 02 -2023 | [📄](https://github.com/code-423n4/2023-01-popcorn-findings/issues/22) | QA Report | B grade |
| RabbitHole Quest Protocol | Code4rena | 30 - 01 -2023 | [📄](https://github.com/code-423n4/2023-01-rabbithole-findings/issues/32) | QA Report | B grade |
| Astaria | Code4rena | 19 - 01 -2023 | [📄](https://github.com/code-423n4/2023-01-astaria-findings/issues/128) | QA Report | B grade |


### Detectors

You can consult the [wiki](https://github.com/seeu-inspace/solidityinspector/wiki) for more information.

| Number | Key | Title | Severity |
| :----- | :- | :--- | -------: |
| 1 | `:bool_storage_overhead` | Avoid Using Boolean Variables for Storage | Gas |
| 2 | `:cache_array_outside_loop` | Array length not cached outside of loop | Gas |
| 3 | `:default_variable_initialization` | Remove Explicit Default Value Assignments | Gas |
| 4 | `:shift_instead_of_divmul` | Use Bitwise Shifting Instead of Multiplication and Division | Gas |
| 5 | `:use_diff_from_0` | Prefer `!= 0` Over `> 0` for Unsigned Integers | Gas |
| 6 | `:long_revert_string` | Optimize `revert` and `require` Strings to Reduce Gas Costs | Gas |
| 7 | `:postfix_increment` | Postfix Increment/Decrement Increases Gas Costs | Gas |
| 8 | `:non_constant_or_immutable_variables` | Use `constant` or `immutable` for Unchanging Variables | Gas |
| 9 | `:public_function` | Use `external` Instead of `public` for Functions When Possible | Gas |
| 10 | `:revert_function_not_payable` | Mark Functions as `payable` When They Are Guaranteed to Revert for Normal Users | Gas |
| 11 | `:assembly_address_zero` | Use Assembly to Check for `address(0)` to Reduce Gas Costs | Gas |
| 12 | `:assert_instead_of_require` | Use `require` Instead of `assert` When Possible | Gas |
| 13 | `:small_uints` | Using `uint` or `int` Smaller Than 32 Bytes Incurs Overhead | Gas |
| 14 | `:use_selfbalance` | Use `selfbalance()` Instead of `address(this).balance` to Reduce Gas Costs | Gas |
| 15 | `:use_immutable` | Using `constant` for Keccak Variables Causes Extra Hashing and Higher Gas Costs | Gas |
| 16 | `:use_require_andand` | Splitting `require()` Statements That Use `&&` Can Reduce Gas Costs | Gas |
| 17 | `:math_gas_cost` | Using `x = x + y` Instead of `x += y` for State Variables Saves Gas | Gas |
| 18 | `:postfix_increment_unchecked` | Use `unchecked{++i}` or `unchecked{i++}` When Overflow Is Not Possible | Gas |
| 19 | `:superfluous_event_fields` | Remove Redundant Event Fields to Save Gas | Gas |
| 20 | `:bool_equals_bool` | Simplify Boolean Comparisons to Reduce Gas and Complexity | Gas |
| 21 | `:strict_comparison` | Use `>=` or `<=` Instead of `>` or `<` to Reduce Gas Costs | Gas |
| 22 | `:private_rather_than_public` | Use `private` Instead of `public` for Constants to Reduce Deployment Gas | Gas |
| 23 | `:use_recent_solidity` | Use a More Recent Solidity Version to Optimize Gas Usage | Gas |
| 24 | `:require_revert_missing_descr` | Add Descriptive Reason Strings to `require()` and `revert()` Statements | Non-Critical |
| 25 | `:unnamed_return_params` | Use Named Return Parameters to Improve Readability | Non-Critical |
| 26 | `:use_of_abi_encodepacked` | Usage of `abi.encodePacked` instead of `bytes.concat()` for Solidity version `>= 0.8.4` | Non-Critical |
| 27 | `:make_modern_import` | Use Explicit Imports for Improved Readability and Efficiency | Non-Critical |
| 28 | `:todo_unfinished_code` | Remove or Track `TODO` Comments to Maintain Code Quality | Non-Critical |
| 29 | `:missing_spdx` | Add `SPDX-License-Identifier` to Avoid Legal and Usage Issues | Non-Critical |
| 30 | `:file_missing_pragma` | Add a `pragma` Statement to Ensure Compiler Compatibility | Non-Critical |
| 31 | `:empty_body` | Add a Comment to Explain Empty Function Bodies | Non-Critical |
| 32 | `:magic_numbers` | Replace Magic Numbers with Named Constants for Better Readability | Non-Critical |
| 33 | `:public_func_not_used_internally` | Use `external` Instead of `public` for Functions Not Called Internally | Non-Critical |
| 34 | `:empty_blocks` | Empty code blocks | Non-Critical |
| 35 | `:inconsistent_types` | Inconsistent Integer Declarations | Non-Critical |
| 36 | `:large_literals` | Large Numeric Literals | Non-Critical |
| 37 | `:state_change_no_event` | Lack of Event Emission for State Changes | Non-Critical |
| 38 | `:abicoder_v2` | Redundant `abicoder v2` Pragma in Solidity `0.8.0+` | Non-Critical |
| 39 | `:abi_encode_unsafe` | Potential Type Safety Issues When Using `abi.encodeWithSignature` or `abi.encodeWithSelector` | Non-Critical |
| 40 | `:constant_naming` | Constants Should Use CONSTANT_CASE | Non-Critical |
| 41 | `:control_structure_style` | Inconsistent Formatting of Control Structures | Non-Critical |
| 42 | `:dangerous_while_loop` | Risk of Infinite Execution Due to `while(true)` Loops | Non-Critical |
| 43 | `:long_lines` | Reduced Readability Due to Excessively Long Lines | Non-Critical |
| 44 | `:mapping_style` | Inconsistent `mapping` Formatting Reduces Readability | Non-Critical |
| 45 | `:hardcoded_address` | Hard-Coded Addresses Reduce Flexibility and Maintainability | Non-Critical |
| 46 | `:safe_math_08` | Redundant Use of SafeMath in Solidity 0.8+ | Non-Critical |
| 47 | `:scientific_notation_exponent` | Use of Exponentiation Instead of Scientific Notation | Non-Critical |
| 48 | `:unspecific_compiler_version_pragma` | Use a Fixed Solidity Version to Ensure Consistent Compilation | Low |
| 49 | `:unsafe_erc20_operations` | Use `SafeERC20` to Prevent Unsafe ERC20 Operations | Low |
| 50 | `:deprecated_oz_library_functions` | Avoid Using Deprecated OpenZeppelin Library Functions | Low |
| 51 | `:abiencoded_dynamic` | Avoid Using `abi.encodePacked()` with Dynamic Types When Hashing | Low |
| 52 | `:transfer_ownership` | Use `safeTransferOwnership` Instead of `transferOwnership` for Safer Ownership Transfers | Low |
| 53 | `:draft_openzeppelin` | Avoid Using Draft OpenZeppelin Contracts | Low |
| 54 | `:use_of_blocktimestamp` | Avoid Relying on `block.timestamp` for Critical Logic | Low |
| 55 | `:calls_in_loop` | Avoid Making External Calls Inside Loops | Low |
| 56 | `:outdated_pragma` | Upgrade to a Recent Solidity Version to Avoid Security Risks | Low |
| 57 | `:ownableupgradeable` | Use `Ownable2StepUpgradeable` Instead of `OwnableUpgradeable` for Safer Ownership Transfers | Low |
| 58 | `:ecrecover_addr_zero` | Ensure `ecrecover()` Does Not Return `address(0)` | Low |
| 59 | `:dont_use_assert` | Use `require` Instead of `assert` to Prevent Gas Wastage | Low |
| 60 | `:deprecated_cl_library_function` | Avoid Using Deprecated Chainlink Library Functions | Low |
| 61 | `:push_0_pragma` | Ensure Compatibility with `PUSH0` Opcode When Using Solidity `≥ 0.8.20` | Low |
| 62 | `:unused_error` | Remove or Implement Unused Error Declarations | Low |
| 63 | `:shadowed_global` | Avoid Shadowing Built-In Global Symbols | Low |
| 64 | `:div_before_mul` | Unsafe Division Before Multiplication | Low |
| 65 | `:uniswap_block_timestamp_deadline` | Lack of Protection When Using `block.timestamp` for Swap Deadlines | Low |
| 66 | `:unused_internal_func` | Unused Internal Functions | Low |
| 67 | `:assembly_in_constant` | Potential Side Effects from Using Assembly in `pure` or `view` Functions | Low |
| 68 | `:costly_loop_operations` | Costly storage operations inside loops | Low |
| 69 | `:reverts_in_loops` | Entire Transaction May Revert Due to `require` / `revert` Inside a Loop | Low |
| 70 | `:decimals_not_erc20` | `decimals()` is not a part of the ERC-20 standard | Low |
| 71 | `:decimals_not_uint8` | `decimals()` should be of type `uint8` | Low |
| 72 | `:fallback_lacking_payable` | Fallback Lacking `payable` | Low |
| 73 | `:symbol_not_erc20` | `symbol()` is not a part of the ERC-20 standard | Low |
| 74 | `:upgradeable_missing_gap` | Risk of Storage Collision Due to Missing Storage Gap in Upgradeable Contract | Low |
| 75 | `:hardcoded_year` | Inaccurate Year Duration Assumption | Low |
| 76 | `:single_point_of_control` | Centralization Risk Due to Single Points of Control | Medium |
| 77 | `:use_safemint` | Use `_safeMint` Instead of `_mint` to Prevent NFT Loss | Medium |
| 78 | `:use_of_cl_lastanswer` | Replace `latestAnswer` with `latestRoundData()` for Reliable Price Feeds | Medium |
| 79 | `:solmate_not_safe` | Use OpenZeppelin's `SafeERC20` Instead of `SafeTransferLib.sol` for Safer Transfers | Medium |
| 80 | `:nested_loop` | Avoid Nested Loops to Prevent Denial of Service | Medium |
| 81 | `:unchecked_recover` | Validate `ECDSA.recover` Output to Prevent Unintended Behavior | Medium |
| 82 | `:unchecked_transfer_transferfrom` | Check the Return Value of `transfer` and `transferFrom` to Prevent Silent Failures | Medium |
| 83 | `:use_of_blocknumber` | Use of `block.number` could lead to different results across EVM chains | Medium |
| 84 | `:stale_check_missing` | Validate Oracle Data Freshness to Prevent Stale Price Usage | Medium |
| 85 | `:tx_origin_usage` | Use of `tx.origin` for Authorization | Medium |
| 86 | `:gas_griefing` | Use Bounded Gas for External Calls to Prevent Gas Griefing Attacks | Medium |
| 87 | `:insecure_randomness` | Avoid Using `blockhash` for Randomness to Prevent Manipulation | Medium |
| 88 | `:delegatecall_in_loop_payable` | Use of `delegatecall` Inside Loops in Payable Function | High |
| 89 | `:arbitrary_from_in_transferFrom` | Arbitrary `from` Address in `transferFrom` / `safeTransferFrom` | High |
| 90 | `:outdated_openzeppelin_contracts` | Outdated version of openzeppelin-contracts | High |
| 91 | `:outdated_openzeppelin_contracts_upgradeable` | Outdated version of openzeppelin-contracts-upgradeable | High |
| 92 | `:msgvalue_in_loop` | Avoid Using `msg.value` Inside Loops to Prevent Logic Errors | High |
| 93 | `:unsafe_casting` | Unsafe type casting | High |
| 94 | `:uninitialized_storage` | Uninitialized Storage Pointer | High |
| 95 | `:get_dy_underlyig_flash_loan` | Price Manipulation Risk Due to Flash Loan Vulnerability in `get_dy_underlying()` | High |
| 96 | `:wsteth_price_steth` | Incorrect Price Calculation When Converting Between `wstETH` and `stETH` | High |
| 97 | `:yul_return_usage` | Unintended Execution Flow Due to `return` Statement in Yul Assembly | High |
| 98 | `:rtlo_character` | RTLO character detected | High |
| 99 | `:multiple_retryable_calls` | Risk of Inconsistent Behavior Due to Multiple Retryable Calls | High |
| 100 | `:contract_locks_ether` | Locked Ether Due to Missing Withdraw Function | High |
