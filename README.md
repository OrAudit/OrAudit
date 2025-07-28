# OrAudit

## Introduction

This repository provides **OrAudit**, the tool introduced in Section.5 of the paper "Towards Secure Oracle Usage: Understanding and Detecting the Vulnerabilities in Oracle Contracts on the Blockchain".

OrAudit is a static analysis tool designed to detect Oracle Consumer Contract Vulnerabilities (OCCVs). It is an extension built on top of [Slither](https://crytic.github.io/slither/slither.html), a widely-used static analysis framework for Solidity.

Specifically, OrAudit extends Slither by implementing three custom detectors:
- [oracle-data-check](https://github.com/OrAudit/OrAudit/blob/main/slither/detectors/functions/oracle_data_check.py)
- [oracle-interface-check](https://github.com/OrAudit/OrAudit/blob/main/slither/detectors/functions/oracle_interface_check.py)
- [oracle-protection-check](https://github.com/OrAudit/OrAudit/blob/main/slither/detectors/functions/oracle_protection_check.py)

These detectors are designed to detect the following types of vulnerabilities:
  
OCCV | Description | Impact | Detector |Confidence
--- | --- | --- | --- | ---
CWE-252 | Missing oracle data availability checks | Medium | oracle-data-check | Medium
CWE-345 | Missing oracle data integrity checks or improper modification of oracle data | High | oracle-data-check | High
CWE-400 | Improper oracle requests or absence of withdrawal interface | Medium | oracle-interface-check | High
CWE-477	| Use of deprecated oracle APIs | Medium | oracle-interface-check | High
CWE-703	| Improper Check or Handling of Exceptional Conditions | Low | oracle-interface-check | High
CWE-284	| Missing access control for oracle config and operations | High | oracle-protection-check | High
CWE-693	| Missing circuit breaker or upgrade mechanism | Low | oracle-protection-check | Medium

For detailed descriptions of these vulnerabilities, please refer to the [OCCV](#OCCV).

## Usage

### Applicability Scope

Currently, OrAudit supports the detection of source code for oracle consumer contracts from four major oracle providers. The supported oracle services are as follows:

Index | Provider | Service | Dependency
--- | --- | --- | ---
1|Chainlink|[Data Feed](https://docs.chain.link/data-feeds)| AggregatorV3Interface, AccessControlledOffchainAggregator
2|Chainlink|[Data Stream](https://docs.chain.link/data-streams)|StreamsLookupCompatibleInterface
3|Chainlink|[Any API](https://docs.chain.link/any-api/introduction)|ChainlinkClient
4|Chainlink|[Functions](https://docs.chain.link/chainlink-functions)|FunctionsClient
5|Chainlink|[VRF](https://docs.chain.link/vrf)|VRFConsumerBaseV2, VRFV2WrapperConsumerBase, VRFConsumerBaseV2Plus, VRFV2PlusWrapperConsumerBase
6|Pyth|[Data Feed](https://docs.pyth.network/price-feeds)|IPyth
7|Pyth|[Data Stream](https://docs.pyth.network/lazer)|PythLazer
8|Pyth|[VRF](https://docs.pyth.network/entropy)|IEntropyConsumer
9|Chronicle|[Data Feed](https://docs.chroniclelabs.org/Developers/start)|IChronicle
10|Redstone|[Data Feed](https://docs.redstone.finance/docs/dapps/redstone-pull/)|RedstoneConsumerBase

### Dependency

Slither requires Python 3.8+ and [solc](https://github.com/ethereum/solidity/), the Solidity compiler. We recommend using [solc-select](https://github.com/crytic/solc-select) to conveniently switch between solc versions according to the detected contracts.

### Installation

```bash
git clone https://github.com/OrAudit/OrAudit.git && cd slither
python3 -m pip install .
```

### Execution Command

For local contracts, please use the following command:
```console
slither --detect oracle-data-check,oracle-interface-check,oracle-protection-check YourContractPath
```

For deployed contracts on Etherscan, please use the following command:
```console
slither --detect oracle-data-check,oracle-interface-check,oracle-protection-check ContractAddreess --etherscan-apikey YourApiKey
```
For contracts deployed on other blockchains, please refer to [Etherscan options](https://github.com/crytic/crytic-compile/wiki/Configuration#etherscan-options) and replace with the corresponding APIKEY.

## OCCV

### CWE-252: Unchecked Return Value

#### Description

It means the user has not checked the availability of the oracle data. The scope of the check should include values, timestamps, market status, sequencer status, etc.

#### Exploit Scenario:

```solidity
interface AggregatorV3Interface {
    function latestRoundData()
        external
        view
        returns (
            uint80 roundID,
            int256 answer,
            uint256 startedAt,
            uint256 updatedAt,
            uint80 answeredInRound
        );
}
contract UnsafeOracleConsumer {
    AggregatorV3Interface public priceFeed;
    constructor(address oracleAddress) {
        priceFeed = AggregatorV3Interface(oracleAddress);
    }
    function getPrice() external view returns (int256) {
        (,int256 price,,,) = priceFeed.latestRoundData();
        // ⚠️ No checks on `price` value or `updatedAt` timestamp
        return price;
}
```
If the availability of oracle data is not checked before use, there is a risk of relying on incorrect or outdated information. It also significantly increases the risk of price manipulation attacks.

#### Recommendation

Ensure that the return format of the oracle employed, and perform appropriate validation on key fields such as value, timestamp, and market status based on your application’s requirements.

### CWE-345: Insufficient Verification of Data Authenticity

#### Description

This vulnerability includes two subtypes:
1. **CWE-345-1: missing oracle data integrity checks**. This refers to the lack of validation on critical metadata associated with oracle responses, such as signatures, caller identity, or sequence numbers. Without such checks, attackers may forge or replay oracle data.
2. **CWE-345-2: improper modification of oracle data**. This refers to unsafe handling or modification of oracle data, where user-controlled parameters or improperly protected state variables can influence the oracle’s output or how it is processed, potentially leading to data manipulation or abuse.

#### Exploit Scenario:

##### CWE-345-1
```solidity
function fulfill(
    bytes32 _requestId,
    uint256 _volume
) public {
    // ⚠️ No validations on the caller or the _requestId
    emit RequestVolume(_requestId, _volume);
    volume = _volume;
}
```
In this scenario, the user should use validateChainlinkCallback interface to ensure that the fulfill function is invoked by the legitimate oracle contract. Additionally, the _requestId parameter should be matched against the previously sent request's identifier to verify its authenticity before storing the corresponding return value.

#### Recommendation
Strictly follow the official developer documentation to validate the callback function call of oracle, and always correlate the response with the corresponding request using the unique requestID.

##### CWE-345-2
```solidity
contract OracleManipulableByUser {
    int256 public userPriceDelta;
    // ⚠️ User can set `userPriceDelta` to manipulate the original oracle value
    function setUserPriceDelta(int _delta) external {
        userPriceDelta = _delta;
    }
    function getPrice() public view returns (int256) {
        (,int256 price,,,) = priceFeed.latestRoundData();
        // ⚠️ Oracle value is manipulated through userPriceDelta
        return rawPrice + userPriceDelta;
    }
}
```
In this scenario, the user-controlled variable userPriceDelta is added to the price, allowing the user to forge a higher or lower price.

#### Recommendation
Before integrating any third-party oracle service, ensure that the oracle data cannot be manipulated by any user within the contract.

### CWE-400: Uncontrolled Resource Consumption

#### Description

This vulnerability includes two subtypes:
1. **CWE-400-1: excessive gas consumption due to improper request**. This refers to scenarios such as sending multiple requests within a single transaction, sending request in loop, or updating states within iterative oracle queries.These situations may result in unexpected failure and significant gas consumption.
2. **CWE-400-2: locked tokens due to absence of withdrawal interface**. This refers to scenarios in which the contract lacks a withdrawal function. It may result in funds being locked since some oracle services are designed to make payments before sending requests. The inability to withdraw excess or unused funds can lead to permanent loss of ETH or LINK held within the contract.

#### Exploit Scenario:

##### CWE-400-1
```solidity
contract HistoricalDataAggregator {
    AggregatorV3Interface internal dataFeed;
    int256 public totalPriceSum;
    function Accumulate(uint80 startRoundId, uint80 endRoundId) external {
        int256 sum = 0;
        // ⚠️ request in loop
        for (uint80 rId = startRoundId; rId <= endRoundId; rId++) {
            (,int256 answer,,uint256 timestamp,) = dataFeed.getRoundData(rId);
            sum += answer;
        }
        // ⚠️ state is changed within the same function
        totalPriceSum += sum;
    }
}
```
In this scenario, both requests in loop and combining iteration over multiple rounds with state modifications significantly increases computational complexity and gas consumption. This design are more possiable to lead to failed transactions, as well as unnecessary gas waste if the transaction reverts.

#### Recommendation
Mark the function that performs oracle requests as view or pure to ensure it does not modify contract state. Additionally, limit each call to handle one request at a time to reduce gas consumption and avoid transaction failure due to excessive gas usage.

##### CWE-400-2
```solidity
contract SimpleAPIConsumer{
    function requestVolumeData() public returns (bytes32 requestId) {
        Chainlink.Request memory req = _buildChainlinkRequest(jobId, address(this), this.fulfill.selector);
        // ⚠️ payment in the contract
        return _sendChainlinkRequest(req, fee);
    }
    function fulfill(bytes32 _requestId, uint256 _volume) public recordChainlinkFulfillment(_requestId) {
        volume = _volume;
        emit RequestVolume(_requestId, _volume);
    }
    // ⚠️ absence of withdrawal interface
}
```
_sendChainlinkRequest attempts to transfer the specified amount of LINK from the contract to the oracle. If the contract lacks a withdrawal function, any excess LINK balance will remain locked.

#### Recommendation

Add withdrawal functions for ETH or other tokens to allow the contract owner to withdraw unused funds.

### CWE-477: Use of Obsolete Function

#### Description
This refers to the use of deprecated APIs within the contract, which affects the availability and security of the functions.

#### Exploit Scenario:

```solidity
contract DeprecatedAPIExample {
    AggregatorV3Interface public priceFeed;
    function getOldPrice(uint80 roundId) public view returns (int256) {
        // ⚠️ getAnswer is DEPRECATED in updated Chainlink aggregators
        return priceFeed.getAnswer(roundId);
    }
}
```

#### Recommendation

Upgrade the contract according to the official developer documentation by replacing deprecated API calls with the recommended alternatives.

### CWE-703: Improper Check or Handling of Exceptional Conditions

#### Description

This vulnerability includes three subtypes:
1. **CWE-703-1: missing request cancellation interface**. This refers to the lack of a cancellation interface for timed-out requests in the contract, which may lead to the waste of resource.
2. **CWE-703-2: missing request error handling interface**. This refers to the situation where, for oracle services that provide specified error checking interfaces for failed requests, the consumer contract does not implement this interfaces and error-handling logic, which may lead to potential security risks.
3. **CWE-703-3: Revert in oracle fulfill function**. This refers to situations where pull oracle requests that require payment may be reverted in the callback function within the contract, which may lead to the waste of resource.

#### Exploit Scenario:

##### CWE-703-1
```solidity
contract SimpleAPIConsumer{
    function requestVolumeData() public returns (bytes32 requestId) {
        Chainlink.Request memory req = _buildChainlinkRequest(jobId, address(this), this.fulfill.selector);
        // ⚠️ payment in the contract
        return _sendChainlinkRequest(req, fee);
    }
    function fulfill(bytes32 _requestId, uint256 _volume) public recordChainlinkFulfillment(_requestId) {
        volume = _volume;
        emit RequestVolume(_requestId, _volume);
    }
    // ⚠️ absence of request cancellation interface
}
```

#### Recommendation
For Chainlink "Connect to Any API" requests, ensure that the consumer contract includes a mechanism to manually cancel pending requests.

##### CWE-703-2
```solidity
contract StreamsUpkeep {
    constructor(address _verifier) {}

    function checkLog(
        Log calldata log,
        bytes memory extraData
    ) external returns (bool upkeepNeeded, bytes memory performData);

    function checkCallback(
        bytes[] calldata values,
        bytes calldata extraData
    ) external pure returns (bool upkeepNeeded, bytes memory performData);

    function performUpkeep(bytes calldata performData) external;
    // ⚠️ absence of check error handler interface
}
```

#### Recommendation
Please implement the checkErrorHandler function in the consumer contract for Chainlink's Data Streams oracle service. If the Automation network fails to retrieve the requested reports, an error code will be sent to your contract's checkErrorHandler function. This function is evaluated off-chain to determine how Automation should do next.

##### CWE-703-3
```solidity
function fulfillRandomWords(
  uint256 requestId,
  uint256[] memory randomWords
) internal override {
  // ⚠️ fulfillRandomWords must not revert
  require(randomWords[0] != 0, "Random word cannot be zero");
  s_randomRange = (randomWords[0] % 50) + 1;
}
```

#### Recommendation
If your fulfill implementation reverts, the oracle service will not attempt to call it a second time. Make sure your fulfill logic does not revert. Consider simply storing the value and taking more complex follow-on actions in separate contract calls.

### CWE-284: Improper Access Control

#### Description
This refers to the lack of access control over critical functions or state variables related to oracle operations, which may lead to unauthorized access or modifications.

#### Exploit Scenario:

```solidity
contract UnsafeOracleContract {
    AggregatorV3Interface public priceFeed;
    // ⚠️ oracle address not protected
    function setPriceFeed(address _priceFeed) public {
        priceFeed = AggregatorV3Interface(_priceFeed);
    }
    function getLatestPrice() public view returns (int256) {
        (,int256 price,,,) = priceFeed.latestRoundData();
        return price;
    }
}
```
The setPriceFeed function lacks proper access control, allowing any user to change the oracle address. Malicious users can redirect the oracle to a fake or manipulated data source

#### Recommendation

Add proper access control mechanisms to critical oracle configuration functions and other sensitive interfaces. Functions such as setting the oracle address or updating key parameters should be restricted to authorized accounts.

### CWE-284: Improper Access Control

#### Description
This refers to the lack of access control over critical functions or state variables related to oracle operations, which may lead to unauthorized access or modifications.

#### Exploit Scenario:

```solidity
contract UnsafeOracleContract {
    AggregatorV3Interface public priceFeed;
    // ⚠️ oracle address not protected
    function setPriceFeed(address _priceFeed) public {
        priceFeed = AggregatorV3Interface(_priceFeed);
    }
    function getLatestPrice() public view returns (int256) {
        (,int256 price,,,) = priceFeed.latestRoundData();
        return price;
    }
}
```
The setPriceFeed function lacks proper access control, allowing any user to change the oracle address. Malicious users can redirect the oracle to a fake or manipulated data source

#### Recommendation

Add proper access control mechanisms to critical oracle configuration functions and other sensitive interfaces. Functions such as setting the oracle address or updating key parameters should be restricted to authorized accounts.

### CWE-693: Protection Mechanism Failure

#### Description
This vulnerability includes three subtypes:

1. **CWE-693-1: missing circuit breaker**. This refers to the absence of a circuit breaker in the contract, meaning that when the oracle services encounter a fault or anomaly, there is no mechanism to prevent the damage frome scalating.
2. **CWE-693-2: missing upgrade mechanism**. This refers to the lack of an upgrade mechanism in the contract, which prevents potential functional defects from being fixed or the contract from meeting new requirements.

#### Recommendation
Implement circuit breaker and upgradeability mechanisms by following OpenZeppelin's Pausable and Upgradeable contract patterns. This allows authorized parties to pause contract functionality in emergency situations and to safely upgrade the contract when necessary, improving security and maintainability.

## License

Slither is licensed and distributed under the AGPLv3 license. [Contact them](mailto:opensource@trailofbits.com) if you're looking for an exception to the terms.