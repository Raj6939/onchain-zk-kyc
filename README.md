
![blue modern business presentation(1)](https://github.com/Raj6939/onchain-zk-kyc/assets/67961128/d79bebb9-405c-4ffd-b7ff-302541c9725e)



# Revolutionizing CrossChain KYC : Elevate Trust with Chainlink Functions and Hypersign DID for Enhanced Privacy and Zero-Knowledge Proof KYC



**Problem Statement**

In the On-chain Zero-Knowledge Proof KYC (ZK-KYC) verification process, when a user submits their Zero-Knowledge Proof to the Verifier Smart Contract, the contract needs to confirm that the proof is legitimate and originates from a valid credential issued by the authorized issuer. In simpler terms, it's like the Verifier making sure that the user has provided evidence (the proof) that they have the right credentials issued by the authorized entity.




**The Solution**


To address the challenge of verifying the Issuer's attestation for the submitted ZK-Proof, we can leverage Chainlink Functions. This allows the Verifier Contract to confirm the validity of the issuer's attestation on any EVM-compatible chain. The process can be visualized through the following simplified diagram. Below is the diagram that visualizes the entire flow.


**Flow Diagram**

![Screenshot from 2023-12-06 01-08-14](https://github.com/Raj6939/onchain-zk-kyc/assets/67961128/84a48506-76dc-40cc-a1e1-6dd85e7d191c)





**Sequence Diagram**

![Screenshot from 2023-12-14 14-29-38](https://github.com/Raj6939/onchain-zk-kyc/assets/67961128/413a173d-3532-4eef-ac0d-fb524ba59ca1)




From the above diagram,at high level, these are the steps:
- **User Submission:** The user submits their Zero-Knowledge Proof to the Business Smart Contract in the form of Verifiable Presentation (VP).
- **ZK-Proof Source Check**: The Businnes Contract utilizes Chainlink Functions to verify the Issuer's attestation for submitted ZK-Proof Presentation by calling Hypersign ID Network. This ensures that the ZK-Proof is associated with a valid credential issued by the authorized Issuer.
- **ZK-Proof Authenticity Check**: Upon successful verification of VP using Chainlink functions, the Businnes Contract needs to check the authenticity of the ZK-Proof, by validating the ZK-Proof from Verifier Smart Contract.
    



**Solidity Business Contract**

```// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

import {FunctionsClient} from "@chainlink/contracts/src/v0.8/functions/dev/v1_0_0/FunctionsClient.sol";
import {ConfirmedOwner} from "@chainlink/contracts/src/v0.8/shared/access/ConfirmedOwner.sol";
import {FunctionsRequest} from "@chainlink/contracts/src/v0.8/functions/dev/v1_0_0/libraries/FunctionsRequest.sol";
import {Groth16Verifier} from "Groth16Verifier.sol";

contract FunctionsConsumerExample is FunctionsClient, ConfirmedOwner {
    using FunctionsRequest for FunctionsRequest.Request;

    bytes32 public s_lastRequestId;
    bytes public s_lastResponse;
    bytes public s_lastError;

    error UnexpectedRequestID(bytes32 requestId);

    event Response(bytes32 indexed requestId, bytes response, bytes err);

    constructor(
        address router
    ) FunctionsClient(router) ConfirmedOwner(msg.sender) {}

    /**
     * @notice Send a simple request
     * @param source JavaScript source code
     * @param encryptedSecretsUrls Encrypted URLs where to fetch user secrets
     * @param donHostedSecretsSlotID Don hosted secrets slotId
     * @param donHostedSecretsVersion Don hosted secrets version
     * @param args List of arguments accessible from within the source code
     * @param bytesArgs Array of bytes arguments, represented as hex strings
     * @param subscriptionId Billing ID
     */
    function sendRequest(
        string memory source,
        bytes memory encryptedSecretsUrls,
        uint8 donHostedSecretsSlotID,
        uint64 donHostedSecretsVersion,
        string[] memory args,
        bytes[] memory bytesArgs,
        uint64 subscriptionId,
        uint32 gasLimit,
        bytes32 donID
    ) external onlyOwner returns (bytes32 requestId) {
        FunctionsRequest.Request memory req;
        req.initializeRequestForInlineJavaScript(source);
        if (encryptedSecretsUrls.length > 0)
            req.addSecretsReference(encryptedSecretsUrls);
        else if (donHostedSecretsVersion > 0) {
            req.addDONHostedSecrets(
                donHostedSecretsSlotID,
                donHostedSecretsVersion
            );
        }
        if (args.length > 0) req.setArgs(args);
        if (bytesArgs.length > 0) req.setBytesArgs(bytesArgs);
        s_lastRequestId = _sendRequest(
            req.encodeCBOR(),
            subscriptionId,
            gasLimit,
            donID
        );
        return s_lastRequestId;
    }

    /**
     * @notice Send a pre-encoded CBOR request
     * @param request CBOR-encoded request data
     * @param subscriptionId Billing ID
     * @param gasLimit The maximum amount of gas the request can consume
     * @param donID ID of the job to be invoked
     * @return requestId The ID of the sent request
     */
    function sendRequestCBOR(
        bytes memory request,
        uint64 subscriptionId,
        uint32 gasLimit,
        bytes32 donID
    ) external onlyOwner returns (bytes32 requestId) {
        s_lastRequestId = _sendRequest(
            request,
            subscriptionId,
            gasLimit,
            donID
        );
        return s_lastRequestId;
    }

    /**
     * @notice Store latest result/error
     * @param requestId The request ID, returned by sendRequest()
     * @param response Aggregated response from the user code
     * @param err Aggregated error from the user code or from the execution pipeline
     * Either response or error parameter will be set, but never both
     */
    function fulfillRequest(
        bytes32 requestId,
        bytes memory response,
        bytes memory err
    ) internal override {
        if (s_lastRequestId != requestId) {
            revert UnexpectedRequestID(requestId);
        }
        s_lastResponse = response;
        s_lastError = err;
        emit Response(requestId, s_lastResponse, s_lastError);
    }

    /**
     * @notice Verify the proof with the provided parameters
     * @param lastRequestId The last request ID to be verified
     * @param lastResponse The last response to be verified
     * @param a Groth16 proof parameter a
     * @param b Groth16 proof parameter b
     * @param c Groth16 proof parameter c
     * @param pubSignals Groth16 proof parameter pubSignals
     * @return true if the verification is successful, false otherwise
     */
    function callVerifyProof(
        bytes32 lastRequestId,
        bytes memory lastResponse,
        uint256[2] memory a,
        uint256[2][2] memory b,
        uint256[2] memory c,
        uint256[1] memory pubSignals
    ) external view returns (bool) {
        // Verify that the provided lastRequestId and lastResponse match the last stored values
        if (lastRequestId != s_lastRequestId || keccak256(lastResponse) != keccak256(s_lastResponse)) {
            return false;
        }

        // Replace verifierContractAddress with the actual address
        address verifierContractAddress = 0x7D5a9AbD3cCf6f68E5DE15968Bc56e13c4014dfF;
        Groth16Verifier verifierContract = Groth16Verifier(verifierContractAddress);

        // Call the verifyProof function with the provided parameters
        return verifierContract.verifyProof(a, b, c, pubSignals);
    }
}
```

**The Above Contract utilizes method (verifyProof) from Verifier Contract**

**Verifier Contract**

```// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity 0.8.19;

contract Groth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 20576316776612924346131171332485464798610324640807048645048471250491423249808;
    uint256 constant alphay  = 10642321740096627355850648777723082240829111043345624215090424286630925494357;
    uint256 constant betax1  = 17947706965765917029482593246351965150489707290959997966664783166885717332715;
    uint256 constant betax2  = 4889639933616333759066497113977711530404971799610976181222952679927065289829;
    uint256 constant betay1  = 19388018702326609682848109091973823137189678386603309310904895349692854321785;
    uint256 constant betay2  = 15386384629106652049512444335083778535780135974787835781550142520718813762980;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 20171323842697838903468403858396180174522494776021316822393088588981861629214;
    uint256 constant deltax2 = 13732142793394296291229804888782706296790626209524502255609481659795712982286;
    uint256 constant deltay1 = 5556707875462008873377836417863099291510935535304624988913336419860749466809;
    uint256 constant deltay2 = 4429918161404727072954335103151854931705172565105190309702988967904406281635;

    
    uint256 constant IC0x = 7152929021430550769973796127968788866470553429782333352910886686307838422742;
    uint256 constant IC0y = 1080199901671684530575089418681939656424262882272933843925127815412640029839;
    
    uint256 constant IC1x = 5431969170227191688007020061682773133604136397111217701616128698575424669090;
    uint256 constant IC1y = 2138272652831160581537903944095797363742914109594667877446295841836321600072;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[1] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, q)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
```


**TODO**

**Note**

> Note: If you want to run this project in local environment then reach out to the Hypersign Team for integration
[Discord](https://discord.gg/zmCj99Mb85)

1. **Hypersign API**

[Optional] To use Hypersign API you can create app in Hypersign Entity Studio, by following the below instructions.
- Visit https://entity.hypersign.id/#/studio/dashboard
- Create App and keep the app ```app secret Key``` with you.
- Learn about the Hypersign API visit the doc here https://docs.hypersign.id/entity-studio/api-doc
- You can also try API Playground swagger implementation here for Hypersign API. https://api.entity.hypersign.id/api

2. **Chainlink Functions**

- Learn Chainlink Functions Doc https://docs.chain.link/chainlink-functions
- Open [Remix](https://remix.ethereum.org/) IDE and create file called ```FunctionsConsumerExample.sol``` and pate above Solidity Business Contract.
- Make sure you have installed Metamsk in the browser and connect it to Remix IDE.
- Deploy the contract with ```router address - 0xb83E47C2bC239B3bf370bc41e1459A34b41238D0``` on Sepolia Network.
- You can learn about supported networks router addresses in [chainlink-supported](https://docs.chain.link/chainlink-functions/supported-networks) doc.
- Copy the deployed Contract address and navigate to the chainlink subscription manager to fund the deployed contract with chainlink tokens. Follow instructions on [this](https://docs.chain.link/chainlink-functions/resources/subscriptions) page
- Once the subscription is created and fund with chainlink tokens. Copy the Consumer Address and Subscription Id.
- No need to deploy Zk Verifier contract as it is deployed already for sepolia network


3. **Clone the below repository**

```https://github.com/hypersign-protocol/dodo-wallet.git```
 
- Checkout to ```chainlink-zk-kyc``` Branch

- Do ```npm install``` (Required node version would be 14.21 or above)

- After installing the dependencies

- Do ```npm run dev```
  If you face an error regarding javascript heap memory out then run the below command
  
  ```NODE_OPTIONS=--max_old_space_size=4096 npm run dev```

- Open the browser and navigate to ```http://localhost:9002```

- Install Metamask Wallet Extension to the browser if you don't have one.

  ```https://metamask.io/download/```
  
**Demo Video**

1. Understanding Problem Statement and Solution
   [Video-1](https://vimeo.com/894507230)

2. Demo Implementation
   [Video-2](https://vimeo.com/894510696?share=copy)







