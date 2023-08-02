// SPDX-License-Identifier: GPL-3.0-or-later
import "../contracts/HDKeyDeriver.sol";

contract HDKeyDeriverTest is KeyDeriver {

    function testHDKeyDerive() public view returns (bytes memory){
        RootKey[] memory pubkeys = new RootKey[](3);
        for (uint256 i = 0; i < 3; i++) {
            pubkeys[i].pubkey = hex"04127644144de44ab1962e32641e64cf5472f01bd0d6d04e6feb4e213a96e58ef3b0db72d036ba5bf8b59fc47583623bb6eb2943b040ee27f3b52a76f123ff022e";
            pubkeys[i].keyType = 2;
        }
        bytes32 keyId = keccak256("discord_handle:1234");
        (bool result, bytes memory pubkey) = computeHDPubKey(keyId, pubkeys);

        if (!result) {
            // error out?
        }

        return pubkey;
    }
}

