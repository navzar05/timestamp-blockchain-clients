// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

contract DocumentRegistry {
    // mapping: 160 bytes key -> hdocument's hash
    mapping(bytes16 => bytes32) public tsp_hashes;

    // event for logs
    event DocumentAdded(bytes16 indexed key, bytes32 hash);

    // adding hash for a specific key
    function addDocument(bytes16 key, bytes32 hash) public {
        require(hash != 0, "Hash invalid");
        tsp_hashes[key] = hash;
        emit DocumentAdded(key, hash);
    }

    // get hash for a key
    function getDocument(bytes16 key) public view returns (bytes32) {
        return tsp_hashes[key];
    }
}
