# SolidityInspector

```Ruby
 __                     ___       _
(_  _  |  o  _| o _|_ \/ | __  _ |_) _  _ _|_ _  __
__)(_) |  | (_| |  |_ / _|_| |_> |  (/_(_  |_(_) |
└───────■ Made with <3 by Riccardo Malatesta (@seeu)
```

[![](https://img.shields.io/badge/ENS-riccardomalatesta.eth-blue)](https://app.ens.domains/riccardomalatesta.eth)
[![License](https://img.shields.io/github/license/seeu-inspace/solidityinspector)](LICENSE)
[![Open Source Love](https://badges.frapsoft.com/os/v1/open-source.svg?v=103)](https://github.com/ellerbrock/open-source-badges/)

A Solidity Static Analyzer made in Ruby designed to assess smart contracts written for code quality, security, and gas optimization issues. SolidityInspector checks for 23 gas, 9 non-critical, 17 low, 8 medium and 5 high issue and creates a markdown report containing the analysis results.

I've created it to help me in the process of learning smart contract auditing and using [c4udit](https://github.com/byterocket/c4udit), [4analy3er](https://github.com/Picodes/4naly3er), [Aderyn](https://github.com/Cyfrin/aderyn) and [Slither](https://github.com/crytic/slither) as inspiration.


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

These reports were generated entirely by SolidityInspector without manual review.

| Project | Platform | Report |
| --- | --- | --- |
| SolidityToken (a personal project) | GitHub | [<img src="img/doc-logo.png" width=18px>](report-examples/solidityinspector_report%23soliditytoken.md) |
| KittensOnChain (a personal project) | GitHub | [<img src="img/doc-logo.png" width=18px>](report-examples/solidityinspector_report%23kittensonchain.md) |


### Detectors

| Number | Key | Title | Severity |
|--------|-----|-------|----------|
| 1 | `:bool_storage_overhead` | [Using bools for storage incurs overhead](https://github.com/seeu-inspace/solidityinspector/wiki#using-bools-for-storage-incurs-overhead) | Gas |
| 2 | `:cache_array_outside_loop` | [Array length not cached outside of loop](https://github.com/seeu-inspace/solidityinspector/wiki#array-length-not-cached-outside-of-loop) | Gas |
| 3 | `:default_variable_initialization` | [Variables initialized with default value](https://github.com/seeu-inspace/solidityinspector/wiki#variables-initialized-with-default-value) | Gas |
| 4 | `:shift_instead_of_divmul` | [Missing implementation Shift Right/Left for division and multiplication](https://github.com/seeu-inspace/solidityinspector/wiki#missing-implementation-shift-rightleft-for-division-and-multiplication) | Gas |
| 5 | `:use_diff_from_0` | [Unsigned integer comparison with `> 0`](https://github.com/seeu-inspace/solidityinspector/wiki#unsigned-integer-comparison-with--0) | Gas |
| 6 | `:long_revert_string` | [Long `revert`/`require` string](https://github.com/seeu-inspace/solidityinspector/wiki#long-revertrequire-string) | Gas |
| 7 | `:postfix_increment` | [Postfix increment/decrement used](https://github.com/seeu-inspace/solidityinspector/wiki#postfix-incrementdecrement-used) | Gas |
| 8 | `:non_constant_or_immutable_variables` | [Variable not constant/immutable](https://github.com/seeu-inspace/solidityinspector/wiki#variable-not-constantimmutable) | Gas |
| 9 | `:public_function` | [Make function external instead of public](https://github.com/seeu-inspace/solidityinspector/wiki#make-function-external-instead-of-public) | Gas |
| 10 | `:revert_function_not_payable` | [Mark payable functions guaranteed to revert when called by normal users](https://github.com/seeu-inspace/solidityinspector/wiki#mark-payable-functions-guaranteed-to-revert-when-called-by-normal-users) | Gas |
| 11 | `:assembly_address_zero` | [Use assembly to check for `address(0)`](https://github.com/seeu-inspace/solidityinspector/wiki#use-assembly-to-check-for-address0) | Gas |
| 12 | `:assert_instead_of_require` | [Use `require` instead of `assert` when possible](https://github.com/seeu-inspace/solidityinspector/wiki#use-require-instead-of-assert-when-possible) | Gas |
| 13 | `:small_uints` | [Usage of uints/ints smaller than 32 bytes (256 bits) incurs overhead](https://github.com/seeu-inspace/solidityinspector/wiki#usage-of-uintsints-smaller-than-32-bytes-256-bits-incurs-overhead) | Gas |
| 14 | `:use_selfbalance` | [Use `selfbalance()` instead of `address(this).balance`](https://github.com/seeu-inspace/solidityinspector/wiki#use-selfbalance-instead-of-addressthisbalance) | Gas |
| 15 | `:use_immutable` | [Usage of constant keccak variables results in extra hashing](https://github.com/seeu-inspace/solidityinspector/wiki#usage-of-constant-keccak-variables-results-in-extra-hashing) | Gas |
| 16 | `:use_require_andand` | [Split `require()` statements that use `&&` to save gas](https://github.com/seeu-inspace/solidityinspector/wiki#split-require-statements-that-use--to-save-gas) | Gas |
| 17 | `:math_gas_cost` | [`x += y` costs more gas than `x = x + y` for state variables](https://github.com/seeu-inspace/solidityinspector/wiki#x--y-costs-more-gas-than-x-x-y-for-state-variables) | Gas |
| 18 | `:postfix_increment_unchecked` | [`++i/i++` should be `unchecked{++i}`/`unchecked{i++}` when it is not possible for them to overflow](https://github.com/seeu-inspace/solidityinspector/wiki#ii-should-be-uncheckediuncheckedi-when-it-is-not-possible-for-them-to-overflow) | Gas |
| 19 | `:superfluous_event_fields` | [Superfluos event fields](https://github.com/seeu-inspace/solidityinspector/wiki#superfluos-event-fields) | Gas |
| 20 | `:bool_equals_bool` | [Use `if(x)` or `if(!x)` instead of `if (x == bool)`](https://github.com/seeu-inspace/solidityinspector/wiki#use-ifx-or-ifx-instead-of-if-x-bool) | Gas |
| 21 | `:strict_comparison` | [When possible, use non-strict comparison `>=` and/or `=<` instead of `>` `<`](https://github.com/seeu-inspace/solidityinspector/wiki#when-possible-use-non-strict-comparison-andor-instead-of) | Gas |
| 22 | `:private_rather_than_public` | [If possible, use private rather than public for constants](https://github.com/seeu-inspace/solidityinspector/wiki#if-possible-use-private-rather-than-public-for-constants) | Gas |
| 23 | `:use_recent_solidity` | [Use a more recent version of Solidity to save gas](https://github.com/seeu-inspace/solidityinspector/wiki#use-a-more-recent-version-of-solidity-to-save-gas) | Gas |
| 24 | `:require_revert_missing_descr` | [`require()`/`revert()` statements should have descriptive reason strings](https://github.com/seeu-inspace/solidityinspector/wiki#requirerevert-statements-should-have-descriptive-reason-strings) | Non-Critical |
| 25 | `:unnamed_return_params` | [Unnamed return parameters](https://github.com/seeu-inspace/solidityinspector/wiki#unnamed-return-parameters) | Non-Critical |
| 26 | `:use_of_abi_encodepacked` | [Usage of `abi.encodePacked` instead of `bytes.concat()` for Solidity version `>= 0.8.4`](https://github.com/seeu-inspace/solidityinspector/wiki#usage-of-abiencodepacked-instead-of-bytesconcat-for-solidity-version-084) | Non-Critical |
| 27 | `:make_modern_import` | [For modern and more readable code; update import usages](https://github.com/seeu-inspace/solidityinspector/wiki#for-modern-and-more-readable-code-update-import-usages) | Non-Critical |
| 28 | `:todo_unfinished_code` | [Code base comments with TODOs](https://github.com/seeu-inspace/solidityinspector/wiki#code-base-comments-with-todos) | Non-Critical |
| 29 | `:missing_spdx` | [`SPDX-License-Identifier` missing](https://github.com/seeu-inspace/solidityinspector/wiki#spdx-license-identifier-missing) | Non-Critical |
| 30 | `:file_missing_pragma` | [File is missing pragma](https://github.com/seeu-inspace/solidityinspector/wiki#file-is-missing-pragma) | Non-Critical |
| 31 | `:empty_body` | [Consider commenting why the body of the function is empty](https://github.com/seeu-inspace/solidityinspector/wiki#consider-commenting-why-the-body-of-the-function-is-empty) | Non-Critical |
| 32 | `:magic_numbers` | [Magic Numbers in contract](https://github.com/seeu-inspace/solidityinspector/wiki#magic-numbers-in-contract) | Non-Critical |
| 33 | `:public_func_not_used_internally` | [`public` function not used internally could be marked as `external`](https://github.com/seeu-inspace/solidityinspector/wiki#public-function-not-used-internally-could-be-marked-as-external) | Non-Critical |
| 34 | `:unspecific_compiler_version_pragma` | [Compiler version Pragma is non-specific](https://github.com/seeu-inspace/solidityinspector/wiki#compiler-version-pragma-is-non-specific) | Low |
| 35 | `:unsafe_erc20_operations` | [Unsafe ERC20 operations](https://github.com/seeu-inspace/solidityinspector/wiki#unsafe-erc20-operations) | Low |
| 36 | `:deprecated_oz_library_functions` | [Deprecated OpenZeppelin library functions](https://github.com/seeu-inspace/solidityinspector/wiki#deprecated-openzeppelin-library-functions) | Low |
| 37 | `:abiencoded_dynamic` | [Avoid using `abi.encodePacked()` with dynamic types when passing the result to a hash function](https://github.com/seeu-inspace/solidityinspector/wiki#usage-of-abiencodepacked-instead-of-bytesconcat-for-solidity-version--084) | Low |
| 38 | `:transfer_ownership` | [Use `safeTransferOwnership` instead of the `transferOwnership` method](https://github.com/seeu-inspace/solidityinspector/wiki#use-safetransferownership-instead-of-the-transferownership-method) | Low |
| 39 | `:use_safemint` | [Use `_safeMint` instead of `_mint`](https://github.com/seeu-inspace/solidityinspector/wiki#use-_safemint-instead-of-_mint) | Low |
| 40 | `:draft_openzeppelin` | [Draft OpenZeppelin dependencies](https://github.com/seeu-inspace/solidityinspector/wiki#draft-openzeppelin-dependencies) | Low |
| 41 | `:use_of_blocktimestamp` | [Timestamp dependency: use of `block.timestamp` (or `now`)](https://github.com/seeu-inspace/solidityinspector/wiki#timestamp-dependency-use-of-blocktimestamp-or-now) | Low |
| 42 | `:calls_in_loop` | [Usage of calls inside of loop](https://github.com/seeu-inspace/solidityinspector/wiki#usage-of-calls-inside-of-loop) | Low |
| 43 | `:outdated_pragma` | [Outdated Compiler Version](https://github.com/seeu-inspace/solidityinspector/wiki#outdated-compiler-version) | Low |
| 44 | `:ownableupgradeable` | [Use `Ownable2StepUpgradeable` instead of `OwnableUpgradeable` contract](https://github.com/seeu-inspace/solidityinspector/wiki#use-ownable2stepupgradeable-instead-of-ownableupgradeable-contract) | Low |
| 45 | `:ecrecover_addr_zero` | [`ecrecover()` does not check for `address(0)`](https://github.com/seeu-inspace/solidityinspector/wiki#ecrecover-does-not-check-for-address0) | Low |
| 46 | `:dont_use_assert` | [Use `require` instead of `assert`](https://github.com/seeu-inspace/solidityinspector/wiki#use-require-instead-of-assert) | Low |
| 47 | `:deprecated_cl_library_function` | [Deprecated ChainLink library function](https://github.com/seeu-inspace/solidityinspector/wiki#deprecated-chainlink-library-function) | Low |
| 48 | `:push_0_pragma` | [Solidity >= 0.8.20 `PUSH0` opcode incompatibility across EVM chains](https://github.com/seeu-inspace/solidityinspector/wiki#solidity--0820-push0-opcode-incompatibility-across-evm-chains) | Low |
| 49 | `:unused_error` | [Declared and not used errors in the contract](https://github.com/seeu-inspace/solidityinspector/wiki#declared-and-not-used-errors-in-the-contract) | Low |
| 50 | `:single_point_of_control` | [Centralization risk detected: contract has a single point of control](https://github.com/seeu-inspace/solidityinspector/wiki#centralization-risk-detected-contract-has-a-single-point-of-control) | Medium |
| 51 | `:use_safemint_msgsender` | [NFT can be frozen in the contract, use `_safeMint` instead of `_mint`](https://github.com/seeu-inspace/solidityinspector/wiki#nft-can-be-frozen-in-the-contract-use-_safemint-instead-of-_mint) | Medium |
| 52 | `:use_of_cl_lastanswer` | [Use of the deprecated `latestAnswer` function in contracts](https://github.com/seeu-inspace/solidityinspector/wiki#use-of-the-deprecated-latestanswer-function-in-contracts) | Medium |
| 53 | `:solmate_not_safe` | [SafeTransferLib.sol does not check if a token is a contract or not](https://github.com/seeu-inspace/solidityinspector/wiki#safetransferlibsol-does-not-check-if-a-token-is-a-contract-or-not) | Medium |
| 54 | `:nested_loop` | [Nested loops could lead to Denial of Service](https://github.com/seeu-inspace/solidityinspector/wiki#nested-loops-could-lead-to-denial-of-service) | Medium |
| 55 | `:unchecked_recover` | [The output of the `ECDSA.recover` function is not checked](https://github.com/seeu-inspace/solidityinspector/wiki#the-output-of-the-ecdsarecover-function-is-not-checked) | Medium |
| 56 | `:unchecked_transfer_transferfrom` | [The result of the `transfer` or `transferFrom` function is not checked](https://github.com/seeu-inspace/solidityinspector/wiki#the-result-of-the-transfer-or-transferfrom-function-is-not-checked) | Medium |
| 57 | `:use_of_blocknumber` | [Use of `block.number` could lead to different results across EVM chains](https://github.com/seeu-inspace/solidityinspector/wiki#use-of-blocknumber-could-lead-to-different-results-across-evm-chains) | Medium |
| 58 | `:delegatecall_in_loop` | [Use of `delegatecall` inside of a loop](https://github.com/seeu-inspace/solidityinspector/wiki#use-of-delegatecall-inside-of-a-loop) | High |
| 59 | `:arbitrary_from_in_transferFrom` | [Arbitrary `from` in `transferFrom` / `safeTransferFrom`](https://github.com/seeu-inspace/solidityinspector/wiki#arbitrary-from-in-transferfrom--safetransferfrom) | High |
| 60 | `:outdated_openzeppelin_contracts` | [Outdated version of openzeppelin-contracts](https://github.com/seeu-inspace/solidityinspector/wiki#outdated-version-of-openzeppelin-contracts) | High |
| 61 | `:outdated_openzeppelin_contracts_upgradeable` | [Outdated version of openzeppelin-contracts-upgradeable](https://github.com/seeu-inspace/solidityinspector/wiki#outdated-version-of-openzeppelin-contracts-upgradeable) | High |
| 62 | `:msgvalue_in_loop` | [Use of `msg.value` inside of a loop](https://github.com/seeu-inspace/solidityinspector/wiki#use-of-msgvalue-inside-of-a-loop) | High |
