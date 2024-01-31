# SolidityInspector

```
 __                     ___       _
(_  _  |  o  _| o _|_ \/ | __  _ |_) _  _ _|_ _  __
__)(_) |  | (_| |  |_ / _|_| |_> |  (/_(_  |_(_) |
└───────■ Made with <3 by Riccardo Malatesta (@seeu)
```

A Ruby script to analyze Solidity smart contracts for code quality, security, and gas optimization issues. I've created it to help me in the process of learning smart contract auditing and using [c4udit](https://github.com/byterocket/c4udit), [4analy3er](https://github.com/Picodes/4naly3er) and [Slither](https://github.com/crytic/slither) as inspiration.

SolidityInspector checks for 23 gas issues, 7 non-critical issues, 14 low issues, 2 medium issues and 2 low to high issue.


## Usage

1. Clone the Repository and Ensure that you have Ruby installed on your system;
2. Run the Script with `ruby solidityinspector.rb`
3. Enter the path to the directory containing the smart contracts to analyze. Ideally, save the directory containing the contracts in the same directory as the script


### Example of usage

```
C:\>ruby solidityinspector.rb
 __                     ___       _
(_  _  |  o  _| o _|_ \/ | __  _ |_) _  _ _|_ _  __
__)(_) |  | (_| |  |_ / _|_| |_> |  (/_(_  |_(_) |
└───────■ Made with <3 by Riccardo Malatesta (@seeu)

Projects in the current directory:
├─ 2023-02-ethos
└─ 2023-03-wenwin

┌─ Enter a directory:
└─ 2023-02-ethos

Files analyzed:
├─ 2023-02-ethos/Ethos-Core/contracts/ActivePool.sol
├─ 2023-02-ethos/Ethos-Core/contracts/BorrowerOperations.sol
├─ 2023-02-ethos/Ethos-Core/contracts/CollSurplusPool.sol
├─ 2023-02-ethos/Ethos-Core/contracts/CollateralConfig.sol
├─ 2023-02-ethos/Ethos-Core/contracts/DefaultPool.sol
├─ 2023-02-ethos/Ethos-Core/contracts/Dependencies/Address.sol
├─ 2023-02-ethos/Ethos-Core/contracts/Dependencies/AggregatorV3Interface.sol
├─ 2023-02-ethos/Ethos-Core/contracts/Dependencies/BaseMath.sol
├─ 2023-02-ethos/Ethos-Core/contracts/Dependencies/CheckContract.sol
├─ 2023-02-ethos/Ethos-Core/contracts/Dependencies/IERC20.sol
├─ 2023-02-ethos/Ethos-Core/contracts/Dependencies/IERC2362.sol
├─ 2023-02-ethos/Ethos-Core/contracts/Dependencies/IERC2612.sol
├─ 2023-02-ethos/Ethos-Core/contracts/Dependencies/IERC4626.sol
├─ 2023-02-ethos/Ethos-Core/contracts/Dependencies/IMappingContract.sol
├─ 2023-02-ethos/Ethos-Core/contracts/Dependencies/ITellor.sol
├─ 2023-02-ethos/Ethos-Core/contracts/Dependencies/LiquityBase.sol
├─ 2023-02-ethos/Ethos-Core/contracts/Dependencies/LiquityMath.sol
├─ 2023-02-ethos/Ethos-Core/contracts/Dependencies/LiquitySafeMath128.sol
├─ 2023-02-ethos/Ethos-Core/contracts/Dependencies/Ownable.sol
├─ [...]
└─ 2023-02-ethos/Ethos-Vault/contracts/mixins/VeloSolidMixin.sol


Using bools for storage incurs overhead Instances (40)
2023-02-ethos/Ethos-Core/contracts/BorrowerOperations.sol
::54 =>         bool isCollIncrease;
::182 =>         bool isRecoveryMode = _checkRecoveryMode(_collateral, vars.price, vars.collCCR, vars.collDecimals);
::290 =>         bool isRecoveryMode = _checkRecoveryMode(_collateral, vars.price, vars.collCCR, vars.collDecimals);
[...]
```


### Detectors

| Number | Key | Title | Severity |
| --- | --- | --- | --- |
| 1 | `bool_storage_overhead` | [Using bools for storage incurs overhead](https://github.com/seeu-inspace/solidityinspector/wiki#using-bools-for-storage-incurs-overhead) | Gas optimization |
| 2 | `cache_array_outside_loop` | [Array length not cached outside of loop](https://github.com/seeu-inspace/solidityinspector/wiki#array-length-not-cached-outside-of-loop) | Gas optimization |
| 3 | `default_variable_initialization` | [Variables initialized with default value](https://github.com/seeu-inspace/solidityinspector/wiki#variables-initialized-with-default-value) | Gas optimization |
| 4 | `shift_instead_of_divmul` | [Missing implementation Shift Right/Left for division and multiplication](https://github.com/seeu-inspace/solidityinspector/wiki#missing-implementation-shift-rightleft-for-division-and-multiplication) | Gas optimization |
| 5 | `use_diff_from_0` | [Unsigned integer comparison with > 0](https://github.com/seeu-inspace/solidityinspector/wiki#unsigned-integer-comparison-with--0) | Gas optimization |
| 6 | `long_revert_string` | [Long revert string](https://github.com/seeu-inspace/solidityinspector/wiki#long-revertrequire-strings) | Gas optimization |
| 7 | `postfix_increment` | [Postfix increment/decrement used](https://github.com/seeu-inspace/solidityinspector/wiki#postfix-incrementdecrement-used) | Gas optimization |
| 8 | `non_constant_or_immutable_variables` | [Variable not constant/immutable](https://github.com/seeu-inspace/solidityinspector/wiki#variable-not-constantimmutable) | Gas optimization |
| 9 | `public_function` | [Make function external instead of public](https://github.com/seeu-inspace/solidityinspector/wiki#make-function-external-instead-of-public) | Gas optimization |
| 10 | `revert_function_not_payable` | [Mark payable functions guaranteed to revert when called by normal users](https://github.com/seeu-inspace/solidityinspector/wiki#mark-payable-functions-guaranteed-to-revert-when-called-by-normal-users) | Gas optimization |
| 11 | `assembly_address_zero` | [Use assembly to check for address(0)](https://github.com/seeu-inspace/solidityinspector/wiki#use-assembly-to-check-for-address0) | Gas optimization |
| 12 | `assert_instead_of_require` | [Use "require" instead of "assert" when possible](https://github.com/seeu-inspace/solidityinspector/wiki#use-require-instead-of-assert-when-possible) | Gas optimization |
| 13 | `small_uints` | [Usage of uints/ints smaller than 32 bytes (256 bits) incurs overhead](https://github.com/seeu-inspace/solidityinspector/wiki#usage-of-uintsints-smaller-than-32-bytes-256-bits-incurs-overhead) | Gas optimization |
| 14 | `use_selfbalance` | [Use selfbalance() instead of address(this).balance](https://github.com/seeu-inspace/solidityinspector/wiki#use-selfbalance-instead-of-addressthisbalance) | Gas optimization |
| 15 | `use_immutable` | [Usage of constant keccak variables results in extra hashing](https://github.com/seeu-inspace/solidityinspector/wiki#usage-of-constant-keccak-variables-results-in-extra-hashing) | Gas optimization |
| 16 | `use_require_andand` | [Split require() statements that use && to save gas](https://github.com/seeu-inspace/solidityinspector/wiki#split-require-statements-that-use--to-save-gas) | Gas optimization |
| 17 | `math_gas_cost` | [x += y costs more gas than x = x + y for state variables](https://github.com/seeu-inspace/solidityinspector/wiki#x--y-costs-more-gas-than-x--x--y-for-state-variables) | Gas optimization |
| 18 | `postfix_increment_unchecked` | [++i/i++ should be unchecked{++i}/unchecked{i++} when it is not possible for them to overflow](https://github.com/seeu-inspace/solidityinspector/wiki#ii-should-be-uncheckediuncheckedi-when-it-is-not-possible-for-them-to-overflow) | Gas optimization |
| 19 | `superfluous_event_fields` | [Superfluos event fields](https://github.com/seeu-inspace/solidityinspector/wiki#superfluos-event-fields) | Gas optimization |
| 20 | `bool_equals_bool` | [Use if(x) or if(!x) instead of if (x == bool)](https://github.com/seeu-inspace/solidityinspector/wiki#use-ifx-or-ifx-instead-of-if-x--bool) | Gas optimization |
| 21 | `strict_comparison` | [When possible, use non-strict comparison >= and/or =< instead of > <](https://github.com/seeu-inspace/solidityinspector/wiki#when-possible-use-non-strict-comparison--andor--instead-of--) | Gas optimization |
| 22 | `private_rather_than_public` | [If possible, use private rather than public for constants](https://github.com/seeu-inspace/solidityinspector/wiki#if-possible-use-private-rather-than-public-for-constants) | Gas optimization |
| 23 | `use_recent_solidity` | [Use a more recent version of Solidity to save gas](https://github.com/seeu-inspace/solidityinspector/wiki#use-a-more-recent-version-of-solidity-to-save-gas) | Gas optimization |
| 24 | `require_revert_missing_descr` | [require()/revert() statements should have descriptive reason strings](https://github.com/seeu-inspace/solidityinspector/wiki#requirerevert-statements-should-have-descriptive-reason-strings) | Non-critical issue |
| 25 | `unnamed_return_params` | [Unnamed return parameters](https://github.com/seeu-inspace/solidityinspector/wiki#unnamed-return-parameters) | Non-critical issue |
| 26 | `use_of_abi_encodepacked` | [Usage of abi.encodePacked instead of bytes.concat() for Solidity version >= 0.8.4](https://github.com/seeu-inspace/solidityinspector/wiki#use-of-abiencodepacked-instead-of-bytesconcat-for-solidity-version--084) | Non-critical issue |
| 27 | `make_modern_import` | [For modern and more readable code; update import usages](https://github.com/seeu-inspace/solidityinspector/wiki#for-modern-and-more-readable-code-update-import-usages) | Non-critical issue |
| 28 | `todo_unfinished_code` | [Code base comments with TODOs](https://github.com/seeu-inspace/solidityinspector/wiki#code-base-comments-with-todos) | Non-critical issue |
| 29 | `missing_spdx` | [SPDX-License-Identifier missing](https://github.com/seeu-inspace/solidityinspector/wiki#spdx-license-identifier-missing) | Non-critical issue |
| 30 | `file_missing_pragma` | [File is missing pragma](https://github.com/seeu-inspace/solidityinspector/wiki#file-is-missing-pragma) | Non-critical issue |
| 31 | `empty_body` | [Consider commenting why the body of the function is empty](https://github.com/seeu-inspace/solidityinspector/wiki#consider-commenting-why-the-body-of-the-function-is-empty) | Low issue |
| 32 | `unspecific_compiler_version_pragma` | [Compiler version Pragma is non-specific](https://github.com/seeu-inspace/solidityinspector/wiki#compiler-version-pragma-is-non-specific) | Low issue |
| 33 | `unsafe_erc20_operations` | [Unsafe ERC20 operations](https://github.com/seeu-inspace/solidityinspector/wiki#unsafe-erc20-operations) | Low issue |
| 34 | `deprecated_oz_library_functions` | [Deprecated OpenZeppelin library functions](https://github.com/seeu-inspace/solidityinspector/wiki#deprecated-openzeppelin-library-functions) | Low issue |
| 35 | `abiencoded_dynamic` | [Avoid using abi.encodePacked() with dynamic types when passing the result to a hash function](https://github.com/seeu-inspace/solidityinspector/wiki#avoid-using-abiencodepacked-with-dynamic-types-when-passing-the-result-to-a-hash-function) | Low issue |
| 36 | `transfer_ownership` | [Use safeTransferOwnership instead of the transferOwnership method](https://github.com/seeu-inspace/solidityinspector/wiki#use-safetransferownership-instead-of-the-transferownership-method) | Low issue |
| 37 | `use_safemint` | [Use _safeMint instead of _mint](https://github.com/seeu-inspace/solidityinspector/wiki#use-_safemint-instead-of-_mint) | Low issue |
| 38 | `draft_openzeppelin` | [Draft OpenZeppelin dependencies](https://github.com/seeu-inspace/solidityinspector/wiki#draft-openzeppelin-dependencies) | Low issue |
| 39 | `use_of_blocktimestamp` | [Timestamp dependency: use of block.timestamp (or now)](https://github.com/seeu-inspace/solidityinspector/wiki#timestamp-dependency) | Low issue |
| 40 | `calls_in_loop` | [Usage of calls inside of loop](https://github.com/seeu-inspace/solidityinspector/wiki#usage-of-calls-inside-of-loop) | Low issue |
| 41 | `outdated_pragma` | [Outdated Compiler Version](https://github.com/seeu-inspace/solidityinspector/wiki#outdated-compiler-version) | Low issue |
| 42 | `ownableupgradeable` | [Use Ownable2StepUpgradeable instead of OwnableUpgradeable contract](https://github.com/seeu-inspace/solidityinspector/wiki#use-ownable2stepupgradeable-instead-of-ownableupgradeable-contract) | Low issue |
| 43 | `ecrecover_addr_zero` | [ecrecover() does not check for address(0)](https://github.com/seeu-inspace/solidityinspector/wiki#ecrecover-does-not-check-for-address0) | Low issue |
| 44 | `dont_use_assert` | [Use require instead of assert](https://github.com/seeu-inspace/solidityinspector/wiki#use-require-instead-of-assert) | Low issue |
| 45 | `single_point_of_control` | [Centralization risk detected: contract has a single point of control](https://github.com/seeu-inspace/solidityinspector/wiki#centralization-risk-contracts-have-a-single-point-of-control) | Medium severity |
| 46 | `use_safemint_msgsender` | [NFT can be frozen in the contract, use _safeMint instead of _mint](https://github.com/seeu-inspace/solidityinspector/wiki#nft-can-be-frozen-in-the-contract) | Medium severity |
| 47 | - | Outdated version of @openzeppelin/contracts ::package.json => Version of @openzeppelin/contracts is #{openzeppelin_version} | High severity |
| 48 | - | Outdated version of @openzeppelin/contracts-upgradeable ::package.json => Version of @openzeppelin/contracts-upgradeable is #{openzeppelin_version} | High severity |


## Example reports

| Contest | Platform | Type of report | Report |
| --- | --- | --- | --- |
| [Wenwin](https://github.com/code-423n4/2023-03-wenwin/) | Code4rena | QA report | [<img src="img/doc-logo.png" width=18px>](report-examples/wenwin-qa-report.md) |
| [Ethos Reserve](https://github.com/code-423n4/2023-02-ethos/) | Code4rena | Gas report | [<img src="img/doc-logo.png" width=18px>](report-examples/ethos-reserve-gas-report.md) |
