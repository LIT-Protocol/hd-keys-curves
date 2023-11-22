// SPDX-License-Identifier: GPL-3.0-or-later
import "../contracts/HDKeyDeriver.sol";

contract HDKeyDeriverTest is KeyDeriver {
    struct RootKey {
        bytes pubkey;
        uint256 keyType; // 1 = BLS, 2 = ECDSA.  Not doing this in an enum so we can add more keytypes in the future without redeploying.
    }

    function testHDKeyDerive() public view returns (bytes memory) {
        bytes[] memory pubkeys = new bytes[](2);

        pubkeys[
            0
        ] = hex"02706ed9fbf152fcc24fa744f727fb3f1e309344f458f6f1ce5ac395785c40b758";
        pubkeys[
            1
        ] = hex"0248a534627a648dc2f3a555ae215d887a38d1983b962a32215a4c8ab01817aed0";

        bytes32 keyId = keccak256("discord_handle:1234");
        (bool result, bytes memory pubkey) = computeHDPubKey(keyId, pubkeys, 1);

        if (!result) {
            revert("result was false, error while generating pubkey");
        }

        return pubkey;
    }
}
