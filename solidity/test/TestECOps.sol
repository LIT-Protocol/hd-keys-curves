//SPDX-License-Identifier: GPL-3.0-or-later

import "forge-std/Test.sol";
import "forge-std/console.sol";

contract TestECOps is Test {
    address public constant BASE_EC_OP_ADDRESS =
        0x000000000000000000000000000000000000012D;

    function testPreCompile() public {
        // proof taken from here https://github.com/LIT-Protocol/hd-keys-ecdsa/blob/main/go/pkg/ec_ops_test.go#L113
        bytes
            memory proof = hex"519d896cca2aef856a7c114e8cfea5a60344ec48ed1a3c7de7e10cc6e74581626de708a97909afe58d51c7df8ba2e4aaa1e99a74ebf0d30ad8a0a20ed5c11d65543d0db0be5d5b8fa2fcaec7c3057a4484c382a2241a944ed3f373400745732cd8073ef502c533f00c028b48d052c03248ed2f5a5cc5e91f24a14c904f3439d72bccafeccd6d820f289edaf48188047e550f2207bc6e1d533845e509884177414c4415bff1ec947b0075e284c7dcf96944da2df8e5686aacdbfe8de141d1af46b30a7d138092b198c014ea9717e884c003105e48dfaf8d09889677eca5d388f306afd5b027b66914b6034cba9f193784c1048321ff6d19f85722c5f47c90758ec8f38ca867f49a479ed383b42abdf289aa023d6af1183c61a9a07e248b75cfc3461294483c05620ff204e437513dbbb84ffacad6941d36b7801f3862d8619070ce"; // bytes of precompile
        (bool success, bytes memory isValid) = BASE_EC_OP_ADDRESS.staticcall(
            proof
        );
        assertEq(success, true);
        console.logString("isValid: ");
        console.logBytes(isValid);
        assertEq(isValid, bytes(hex"01"));
    }
}
