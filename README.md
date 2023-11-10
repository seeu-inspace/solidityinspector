# SolidityInspector
```
 __                     ___       _
(_  _  |  o  _| o _|_ \/ | __  _ |_) _  _ _|_ _  __
__)(_) |  | (_| |  |_ / _|_| |_> |  (/_(_  |_(_) |
└───────■ Made with <3 by Riccardo Malatesta (@seeu)
```

A Ruby script to analyze Solidity smart contracts for code quality, security, and gas optimization issues. I've created it to help me in the process of learning smart contract auditing and using [c4udit](https://github.com/byterocket/c4udit), [4analy3er](https://github.com/Picodes/4naly3er) and [Slither](https://github.com/crytic/slither) as inspiration.

SolidityInspector checks for 23 gas issues, 7 non-critical issues, 15 low issues, 3 medium issues and 1 high issue.

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

## Example reports

| Contest | Platform | Type of report | Report |
| --- | --- | --- | --- |
| [Wenwin](https://github.com/code-423n4/2023-03-wenwin/) | Code4rena | QA report | [<img src="img/doc-logo.png" width=18px>](report-examples/wenwin-qa-report.md) |
| [Ethos Reserve](https://github.com/code-423n4/2023-02-ethos/) | Code4rena | Gas report | [<img src="img/doc-logo.png" width=18px>](report-examples/ethos-reserve-gas-report.md) |
