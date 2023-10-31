| Index |
| --- |
| [Low issues](#low-issues) |
| [Non-Critical issues](#non-critical-issues) |


# Low issues

| ID                                                       | Issue                                      | Contexts | Instances |
| -------------------------------------------------------- | ------------------------------------------ | -------- | --------- |
| [L-01](#l-01-outdated-compiler-version) | Outdated Compiler Version | 2 | 2 |
| [L-02](#l-02-compiler-version-pragma-is-non-specific) | Compiler version Pragma is non-specific | 2 | 2 |
| [L-03](#l-03-use-_safemint-instead-of-_mint) | Use `_safeMint` instead of `_mint` | 3 | 4 |
| [L-04](#l-04-use-require-instead-of-assert) | Use require instead of assert | 2 | 2 |
| [L-05](#l-05-decimals-is-not-part-of-erc20-standard-and-it-may-fail) | decimals() is not part of ERC20 standard and it may fail | 1 | 3 |
| [L-06](#l-06-timestamp-dependency) | Timestamp dependency | 4 | 11 |



| Total issues | Total contexts | Total instances |
| ------------ | -------------- | --------------- |
| 6            | 14             | 24              |


## [L-01] Outdated Compiler Version

### Description

Using an older compiler version might be risky, especially if the version in question has faults and problems that have been made public.

### Findings

- [src/VRFv2RNSource.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/VRFv2RNSource.sol) => `^0.8.7`
- [src/interfaces/IVRFv2RNSource.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/interfaces/IVRFv2RNSource.sol) => `^0.8.7`

### References

- [SWC-102](https://swcregistry.io/docs/SWC-102)
- [Etherscan Solidity Bug Info](https://etherscan.io/solcbuginfo)

## [L-02] Compiler version Pragma is non-specific

### Description

For non-library contracts, floating pragmas may be a security risk for application implementations, since a known vulnerable compiler version may accidentally be selected or security tools might fallback to an older compiler version ending up checking a different EVM compilation that is ultimately deployed on the blockchain.

### Findings

- [src/VRFv2RNSource.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/VRFv2RNSource.sol) => `pragma solidity ^0.8.7;`
- [src/staking/StakedTokenLock.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/staking/StakedTokenLock.sol) => `pragma solidity ^0.8.17;`

### References

- [L003 - Unspecific Compiler Version Pragma](https://github.com/byterocket/c4-common-issues/blob/main/2-Low-Risk.md#l003---unspecific-compiler-version-pragma)
- [Version Pragma | Solidity documents](https://docs.soliditylang.org/en/latest/layout-of-source-files.html#version-pragma)
- [4.6 Unspecific compiler version pragma | Consensys Audit of 1inch Liquidity Protocol](https://consensys.net/diligence/audits/2020/12/1inch-liquidity-protocol/#unspecific-compiler-version-pragma)

## [L-03] Use `_safeMint` instead of `_mint`

### Description

In favor of `_safeMint()`, which guarantees that the receiver is either an EOA or implements IERC721Receiver, `_mint()` is deprecated.

### Findings

- [src/LotteryToken.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/LotteryToken.sol)
  ```Solidity
  ::19 =>         _mint(msg.sender, INITIAL_SUPPLY);
  ::26 =>         _mint(account, amount);
  ```
- [src/Ticket.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/Ticket.sol)
  ```Solidity
  ::26 =>         _mint(to, ticketId);
  ```
- [src/staking/Staking.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/staking/Staking.sol)
  ```Solidity
  ::74 =>         _mint(msg.sender, amount);
  ```

### References
- [OpenZeppelin warning ERC721.sol#L271](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/d4d8d2ed9798cc3383912a23b5e8d5cb602f7d4b/contracts/token/ERC721/ERC721.sol#L271)
- [solmate _safeMint](https://github.com/transmissions11/solmate/blob/4eaf6b68202e36f67cab379768ac6be304c8ebde/src/tokens/ERC721.sol#L180)
- [OpenZeppelin _safeMint](https://github.com/OpenZeppelin/openzeppelin-contracts/blob/d4d8d2ed9798cc3383912a23b5e8d5cb602f7d4b/contracts/token/ERC721/ERC721.sol#L238-L250)


## [L-04] Use require instead of assert

### Description

It is reccomended to use `require` instead of `assert` since the latest, when false, uses up all the remaining gas and reverts all the changes made.

### Findings

- [src/LotterySetup.sol#L147](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/LotterySetup.sol#L147)
  ```Solidity
  assert(initialPot > 0);
  ```
- [src/TicketUtils.sol#L99](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/TicketUtils.sol#L99)
  ```Solidity
  assert((winTier <= selectionSize) && (intersection == uint256(0)));
  ```

### References

- [Require vs Assert in Solidity](https://dev.to/tawseef/require-vs-assert-in-solidity-5e9d)


## [L-05] decimals() is not part of ERC20 standard and it may fail

### Description

Since `decimals()` is not a part of the official ERC20 standard, it could not work for some tokens.

### Findings

- [src/LotterySetup.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/LotterySetup.sol)
  ```Solidity
  ::79 =>         uint256 tokenUnit = 10 ** IERC20Metadata(address(lotterySetupParams.token)).decimals();
  ::128 =>             return extracted * (10 ** (IERC20Metadata(address(rewardToken)).decimals() - 1));
  ::168 =>         uint256 divisor = 10 ** (IERC20Metadata(address(rewardToken)).decimals() - 1);
  ```

### References

- [[L-02] DECIMALS() NOT PART OF ERC20 STANDARD](https://code4rena.com/reports/2022-07-axelar#l-02-decimals-not-part-of-erc20-standard)


## [L-06] Timestamp dependency

### Description

The timestamp of a block is provided by the miner who mined the block. As a result, the timestamp is not guaranteed to be accurate or to be the same across different nodes in the network. In particular, an attacker can potentially mine a block with a timestamp that is favorable to them, known as "selective packing".

For example, an attacker could mine a block with a timestamp that is slightly in the future, allowing them to bypass a time-based restriction in a smart contract that relies on `block.timestamp`. This could potentially allow the attacker to execute a malicious action that would otherwise be blocked by the restriction.

It is reccomended to, instead, use an alternative timestamp source, such as an oracle, that is not susceptible to manipulation by a miner.

### Findings

- [src/Lottery.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/Lottery.sol)
  ```Solidity
  ::135 =>         if (block.timestamp < drawScheduledAt(currentDraw)) {
  ::164 =>             if (block.timestamp <= ticketRegistrationDeadline(ticketInfo.drawId + LotteryMath.DRAWS_PER_YEAR)) {
  ```
- [src/LotterySetup.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/LotterySetup.sol)
  ```Solidity
  ::74 =>         if (initialPotDeadline < (block.timestamp + lotterySetupParams.drawSchedule.drawPeriod)) {
  ::114 =>         if (block.timestamp > ticketRegistrationDeadline(drawId)) {
  ::137 =>         if (block.timestamp <= initialPotDeadline) {
  ```
- [src/RNSourceController.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/RNSourceController.sol)
  ```Solidity
  ::64 =>         if (block.timestamp - lastRequestTimestamp <= maxRequestDelay) {
  ::70 =>             maxFailedAttemptsReachedAt = block.timestamp;
  ::94 =>         bool notEnoughTimeReachingMaxFailedAttempts = block.timestamp < maxFailedAttemptsReachedAt + maxRequestDelay;
  ::107 =>         lastRequestTimestamp = block.timestamp;
  ```
- [src/staking/StakedTokenLock.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/staking/StakedTokenLock.sol)
  ```Solidity
  ::26 =>         if (block.timestamp > depositDeadline) {
  ::39 =>         if (block.timestamp > depositDeadline && block.timestamp < depositDeadline + lockDuration) {
  ```

### References
- [Timestamp dependence | Solidity Best Practices for Smart Contract Security](https://consensys.net/blog/developers/solidity-best-practices-for-smart-contract-security/)
- [What Is Timestamp Dependence?](https://halborn.com/what-is-timestamp-dependence/)

# Non-Critical issues

| ID    | Issue | Contexts | Instances |
| ----- | ----- | -------- | --------- |
| [NC-01](#nc-01-unnamed-return-parameters) | Unnamed return parameters | 1 | 1 |
| [NC-02](#nc-02-pragma-version-0817-too-recent-to-be-trusted) | Pragma Version 0.8.17 too recent to be trusted | 1 | 1 |
| [NC-03](#nc-03-for-modern-and-more-readable-code-update-import-usages) | For modern and more readable code; update import usages | 20 | 53 |


| Total issues | Total contexts | Total instances |
| ------------ | -------------- | --------------- |
| 3            | 22             | 55              |

## [NC-01] Unnamed return parameters

### Description

To increase explicitness and readability, take into account introducing and utilizing named return parameters.

### Findings

- [src/LotterySetup.sol#L160](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/LotterySetup.sol#L160)
  ```Solidity
  function _baseJackpot(uint256 _initialPot) internal view returns (uint256) {
  ```

### References

- [Unnamed return parameters | Opyn Bull Strategy Contracts Audit](https://blog.openzeppelin.com/opyn-bull-strategy-contracts-audit/#unnamed-return-parameters)


## [NC-02] Pragma Version 0.8.17 too recent to be trusted

### Description

In recert versions, unexpected problems might be reported. Use a more robust, non-legacy version like `0.8.10`.

### Findings

- [src/staking/StakedTokenLock.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/staking/StakedTokenLock.sol) => `^0.8.17`

### References

- [Ethereum Solidity changelog](https://github.com/ethereum/solidity/blob/develop/Changelog.md)
- [[N-09] PRAGMA VERSION^0.8.17 VERSION TOO RECENT TO BE TRUSTED.](https://code4rena.com/reports/2022-12-caviar/#n-09-pragma-version0817--version-too-recent-to-be-trusted)

## [NC-03] For modern and more readable code; update import usages

### Description

A less obvious way that solidity code is clearer is the struct Point. Prior to now, we imported it via global import, but we didn't use it. The Point struct contaminated the source code with an extra object that was not needed and that we were not utilizing.

To be sure to only import what you need, use specific imports using curly brackets.

### Findings

- [src/Lottery.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/Lottery.sol)
  ```Solidity
  ::5 => import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
  ::6 => import "@openzeppelin/contracts/utils/math/Math.sol";
  ::7 => import "src/ReferralSystem.sol";
  ::8 => import "src/RNSourceController.sol";
  ::9 => import "src/staking/Staking.sol";
  ::10 => import "src/LotterySetup.sol";
  ::11 => import "src/TicketUtils.sol";
  ```
- [src/LotteryMath.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/LotteryMath.sol)
  ```Solidity
  ::5 => import "src/interfaces/ILottery.sol";
  ::6 => import "src/PercentageMath.sol";
  ```
- [src/LotterySetup.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/LotterySetup.sol)
  ```Solidity
  ::5 => import "@openzeppelin/contracts/utils/math/Math.sol";
  ::6 => import "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
  ::7 => import "src/PercentageMath.sol";
  ::8 => import "src/LotteryToken.sol";
  ::9 => import "src/interfaces/ILotterySetup.sol";
  ::10 => import "src/Ticket.sol";
  ```
- [src/LotteryToken.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/LotteryToken.sol)
  ```Solidity
  ::5 => import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
  ::6 => import "src/interfaces/ILotteryToken.sol";
  ::7 => import "src/LotteryMath.sol";
  ```
- [src/RNSourceBase.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/RNSourceBase.sol)
  ```Solidity
  ::5 => import "src/interfaces/IRNSource.sol";
  ```
- [src/RNSourceController.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/RNSourceController.sol)
  ```Solidity
  ::5 => import "@openzeppelin/contracts/access/Ownable2Step.sol";
  ::6 => import "src/interfaces/IRNSource.sol";
  ::7 => import "src/interfaces/IRNSourceController.sol";
  ```
- [src/ReferralSystem.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/ReferralSystem.sol)
  ```Solidity
  ::5 => import "@openzeppelin/contracts/utils/math/Math.sol";
  ::6 => import "src/interfaces/IReferralSystem.sol";
  ::7 => import "src/PercentageMath.sol";
  ```
- [src/Ticket.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/Ticket.sol)
  ```Solidity
  ::5 => import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
  ::6 => import "src/interfaces/ITicket.sol";
  ```
- [src/VRFv2RNSource.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/VRFv2RNSource.sol)
  ```Solidity
  ::5 => import "@chainlink/contracts/src/v0.8/VRFV2WrapperConsumerBase.sol";
  ::6 => import "src/interfaces/IVRFv2RNSource.sol";
  ::7 => import "src/RNSourceBase.sol";
  ```
- [src/interfaces/ILottery.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/interfaces/ILottery.sol)
  ```Solidity
  ::5 => import "src/interfaces/ILotterySetup.sol";
  ::6 => import "src/interfaces/IRNSourceController.sol";
  ::7 => import "src/interfaces/ITicket.sol";
  ::8 => import "src/interfaces/IReferralSystem.sol";
  ```
- [src/interfaces/ILotterySetup.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/interfaces/ILotterySetup.sol)
  ```Solidity
  ::5 => import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
  ::6 => import "src/interfaces/ITicket.sol";
  ```
- [src/interfaces/ILotteryToken.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/interfaces/ILotteryToken.sol)
  ```Solidity
  ::5 => import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
  ```
- [interfaces/IRNSourceController.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/interfaces/IRNSourceController.sol)
  ```Solidity
  ::5 => import "@openzeppelin/contracts/access/Ownable2Step.sol";
  ::6 => import "src/interfaces/IRNSource.sol";
  ```
- [src/interfaces/IReferralSystem.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/interfaces/IReferralSystem.sol)
  ```Solidity
  ::5 => import "src/interfaces/ILotteryToken.sol";
  ```
- [src/interfaces/ITicket.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/interfaces/ITicket.sol)
  ```Solidity
  ::5 => import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
  ```
- [src/interfaces/IVRFv2RNSource.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/interfaces/IVRFv2RNSource.sol)
  ```Solidity
  ::5 => import "src/interfaces/IRNSource.sol";
  ```
- [src/staking/StakedTokenLock.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/staking/StakedTokenLock.sol)
  ```Solidity
  ::5 => import "@openzeppelin/contracts/access/Ownable2Step.sol";
  ::6 => import "src/staking/interfaces/IStakedTokenLock.sol";
  ::7 => import "src/staking/interfaces/IStaking.sol";
  ```
- [src/staking/Staking.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/staking/Staking.sol)
  ```Solidity
  ::5 => import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
  ::6 => import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
  ::7 => import "src/interfaces/ILottery.sol";
  ::8 => import "src/LotteryMath.sol";
  ::9 => import "src/staking/interfaces/IStaking.sol";
  ```
- [src/staking/interfaces/IStakedTokenLock.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/staking/interfaces/IStakedTokenLock.sol)
  ```Solidity
  ::5 => import "src/staking/interfaces/IStaking.sol";
  ```
- [staking/interfaces/IStaking.sol](https://github.com/code-423n4/2023-03-wenwin/tree/main/src/staking/interfaces/IStaking.sol)
  ```Solidity
  ::5 => import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
  ::6 => import "src/interfaces/ILottery.sol";
  ```

### References

- [[N-03] FOR MODERN AND MORE READABLE CODE; UPDATE IMPORT USAGES | PoolTogether contest](https://code4rena.com/reports/2022-12-pooltogether#n-03-for-modern-and-more-readable-code-update-import-usages)
