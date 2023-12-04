// SPDX-License-Identifier: GPL-3.0-or-later
import "../contracts/HDKeyDeriver.sol";
import "forge-std/console.sol";
import "forge-std/Test.sol";

contract HDKeyDeriverTest is KeyDeriver, Test {
    struct RootKey {
        bytes pubkey;
        uint256 keyType; // 1 = BLS, 2 = ECDSA.  Not doing this in an enum so we can add more keytypes in the future without redeploying.
    }

    function testHDKeyDerive() public returns (bytes memory) {
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

        console.logString("pubkey: ");
        console.logBytes(pubkey);
        assertEq(pubkey.length, 65);
        assertEq(pubkey[0], hex"04");
        assertEq(
            pubkey,
            hex"04dd4bcde9098cf1f26613af620ff11e5c51100cf2dafa80f3d8441bd42f8ce6b8e2d4119b95400c50dcbe6e0552ab44ae865cc39278ac8d7e2573bc45ad1941de"
        );

        return pubkey;
    }
}
