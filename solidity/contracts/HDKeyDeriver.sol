//SPDX-License-Identifier: GPL-3.0-or-later

pragma solidity ^0.8.17;
import "solidity-bytes-utils/contracts/BytesLib.sol";

library HDKeyDeriver {
    using BytesLib for bytes;
    
    struct RootKey {
        bytes pubkey;
        uint256 keyType;
    }

    struct HDKeyParams {
        bytes32 derivedKeyId;
        RootKey[] hdRootKeys;
    }

    // address for HD public KDF
    address public constant HD_KDF = 0x0000000000000000000000000000000000000100;
    // hd kdf ctx
    string constant HD_KDF_CTX = "LIT_HD_KEY_ID_K256_XMD:SHA-256_SSWU_RO_NUL_";

    function computeHDPubKey(
        bytes32 derivedKeyId,
        RootKey[] memory rootHDKeys
    ) public view returns (bool, bytes memory) {
        bytes memory args = buildArgs(derivedKeyId, rootHDKeys);
        (bool success, bytes memory data) = HD_KDF.staticcall(args);
        return (success, data);
    }

    function buildArgs(
        bytes32 derivedKeyId,
        RootKey[] memory rootHDKeys
    ) public pure returns (bytes memory) {
        // empty array for concating pubkeys
        bytes memory rootPubkeys = new bytes(0); // each key is 33 bytes
        for (uint256 i = 0; i < rootHDKeys.length; i++) {
            // console.log(rootHDKeys[i].pubkey.length);
            rootPubkeys = rootPubkeys.concat(rootHDKeys[i].pubkey);
        }

        uint8 kt = uint8(rootHDKeys[0].keyType);
        bytes memory CTX = bytes(HD_KDF_CTX);
        bytes memory args_bytes = abi.encodePacked(
            bytes1(kt), // 1st arg is a byte for the curve type, 0 is Nist Prime256, 1 is secp256k1
            bytes4(uint32(32)), // 2nd arg is a 4 byte big-endian integer for the number of bytes in id
            derivedKeyId, // 3rd arg is the byte sequence for id
            bytes4(uint32(CTX.length)), // 4th arg is a 4 byte big-endian integer for the number of bytes in cxt
            CTX, // 5th arg is the byte sequence for cxt
            bytes4(uint32(rootHDKeys.length)), // 6th arg is a 4 byte big-endian integer for the number of root keys
            rootPubkeys // 7th arg is a variable number of root keys each 33 bytes in length
        );
       // console.log("========built arguments========");
       // console.logBytes(args_bytes);
        return args_bytes;
    }
}