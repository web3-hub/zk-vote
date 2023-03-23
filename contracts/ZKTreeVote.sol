// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "zk-merkle-tree/contracts/ZKTree.sol";

contract ZKTreeVote is ZKTree {
    address public owner;
    mapping(address => bool) public validators;
    mapping(uint256 => bool) uniqueHashes;
    mapping(uint => uint) optionCounter;
    string public votesEncodingKey;
    string public votesDecodingKey;
    string[] public encodedVotes;

    constructor(
        uint32 _levels,
        IHasher _hasher,
        IVerifier _verifier,
        string memory _votesEncodingKey
    ) ZKTree(_levels, _hasher, _verifier) {
        owner = msg.sender;
        votesEncodingKey = _votesEncodingKey;
    }

    function registerValidator(address _validator) external {
        require(msg.sender == owner, "Only owner can add validator!");
        validators[_validator] = true;
    }

    function registerCommitment(
        uint256 _uniqueHash,
        uint256 _commitment
    ) external {
        require(validators[msg.sender], "Only validator can commit!");
        require(
            !uniqueHashes[_uniqueHash],
            "This unique hash is already used!"
        );
        _commit(bytes32(_commitment));
        uniqueHashes[_uniqueHash] = true;
    }

    function vote(
        string memory _encodedOption,
        uint256 _nullifier,
        uint256 _root,
        uint[2] memory _proof_a,
        uint[2][2] memory _proof_b,
        uint[2] memory _proof_c
    ) external {
        _nullify(
            bytes32(_nullifier),
            bytes32(_root),
            _proof_a,
            _proof_b,
            _proof_c
        );
        encodedVotes.push(_encodedOption);
    }

    function revealVotesDecodingKey(string memory _voteDecodingKey) external {
        votesDecodingKey = _voteDecodingKey;
    }

    function getVotesLength() public view returns(uint) {
        return encodedVotes.length;
    }

    function getVotesPage(uint skip, uint pageSize) public view returns(string[] memory) {
        string[] memory page = new string[](pageSize);
        for (uint i = 0; i < pageSize; i ++) {
            page[i] = encodedVotes[i + skip];
        }
        return page;
    }
}
