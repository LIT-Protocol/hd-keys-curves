// SPDX-License-Identifier: GPL-3.0-or-later
import "../contracts/HDKeyDeriver.sol";

contract HDKeyDeriverTest is KeyDeriver {

    function testHDKeyDerive() public view returns (bytes memory){
        RootKey[] memory pubkeys = new RootKey[](2);
       
        pubkeys[0].pubkey = hex"02706ed9fbf152fcc24fa744f727fb3f1e309344f458f6f1ce5ac395785c40b758";
        pubkeys[0].keyType = 1;
        pubkeys[1].pubkey = hex"0248a534627a648dc2f3a555ae215d887a38d1983b962a32215a4c8ab01817aed0";
	    pubkeys[1].keyType = 1;
        
        bytes32 keyId = keccak256("discord_handle:1234");
        (bool result, bytes memory pubkey) = computeHDPubKey(keyId, pubkeys);

        if (!result) {
            revert("result was false, error while generating pubkey");
        }

        return pubkey;
    }
}


