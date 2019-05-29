// Copyright (c) 2018, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include <stdio.h>

#include <stdlib.h>

#include <turtlecoin-crypto.h>

#include <emscripten/bind.h>

using namespace emscripten;

EMSCRIPTEN_BINDINGS(signatures)
{
    function("cn_fast_hash", &Core::Cryptography::cn_fast_hash);

#ifdef HASHFUNCTIONS
    function("cn_slow_hash_v0", &Core::Cryptography::cn_slow_hash_v0);
    function("cn_slow_hash_v1", &Core::Cryptography::cn_slow_hash_v1);
    function("cn_slow_hash_v2", &Core::Cryptography::cn_slow_hash_v2);
    
    function("cn_lite_slow_hash_v0", &Core::Cryptography::cn_lite_slow_hash_v0);
    function("cn_lite_slow_hash_v1", &Core::Cryptography::cn_lite_slow_hash_v1);
    function("cn_lite_slow_hash_v2", &Core::Cryptography::cn_lite_slow_hash_v2);
    
    function("cn_dark_slow_hash_v0", &Core::Cryptography::cn_dark_slow_hash_v0);
    function("cn_dark_slow_hash_v1", &Core::Cryptography::cn_dark_slow_hash_v1);
    function("cn_dark_slow_hash_v2", &Core::Cryptography::cn_dark_slow_hash_v2);
    
    function("cn_dark_lite_slow_hash_v0", &Core::Cryptography::cn_dark_lite_slow_hash_v0);
    function("cn_dark_lite_slow_hash_v1", &Core::Cryptography::cn_dark_lite_slow_hash_v1);
    function("cn_dark_lite_slow_hash_v2", &Core::Cryptography::cn_dark_lite_slow_hash_v2);
    
    function("cn_turtle_slow_hash_v0", &Core::Cryptography::cn_turtle_slow_hash_v0);
    function("cn_turtle_slow_hash_v1", &Core::Cryptography::cn_turtle_slow_hash_v1);
    function("cn_turtle_slow_hash_v2", &Core::Cryptography::cn_turtle_slow_hash_v2);
    
    function("cn_turtle_lite_slow_hash_v0", &Core::Cryptography::cn_turtle_lite_slow_hash_v0);
    function("cn_turtle_lite_slow_hash_v1", &Core::Cryptography::cn_turtle_lite_slow_hash_v1);
    function("cn_turtle_lite_slow_hash_v2", &Core::Cryptography::cn_turtle_lite_slow_hash_v2);
    
    function("cn_soft_shell_slow_hash_v0", &Core::Cryptography::cn_soft_shell_slow_hash_v0);
    function("cn_soft_shell_slow_hash_v1", &Core::Cryptography::cn_soft_shell_slow_hash_v1);
    function("cn_soft_shell_slow_hash_v2", &Core::Cryptography::cn_soft_shell_slow_hash_v2);
    
    function("chukwa_slow_hash", &Core::Cryptography::chukwa_slow_hash);
#endif

    function("tree_hash", &Core::Cryptography::tree_hash);
    function("tree_branch", &Core::Cryptography::tree_branch);
    function("tree_hash_from_branch", &Core::Cryptography::tree_hash_from_branch);
    
    function("generateRingSignatures", &Core::Cryptography::generateRingSignatures);
    function("checkRingSignature", &Core::Cryptography::checkRingSignature);
    function("generatePrivateViewKeyFromPrivateSpendKey", &Core::Cryptography::generatePrivateViewKeyFromPrivateSpendKey);
    function("generateViewKeysFromPrivateSpendKey", &Core::Cryptography::generateViewKeysFromPrivateSpendKey);
    function("generateKeys", &Core::Cryptography::generateKeys);
    function("checkKey", &Core::Cryptography::checkKey);
    function("secretKeyToPublicKey", &Core::Cryptography::secretKeyToPublicKey);
    function("generateKeyDerivation", &Core::Cryptography::generateKeyDerivation);
    function("derivePublicKey", &Core::Cryptography::derivePublicKey);
    function("deriveSecretKey", &Core::Cryptography::deriveSecretKey);
    function("underivePublicKey", &Core::Cryptography::underivePublicKey);
    function("generateSignature", &Core::Cryptography::generateSignature);
    function("checkSignature", &Core::Cryptography::checkSignature);
    function("generateKeyImage", &Core::Cryptography::generateKeyImage);
    function("scalarmultKey", &Core::Cryptography::scalarmultKey);
    function("hashToEllipticCurve", &Core::Cryptography::hashToEllipticCurve);
    function("scReduce32", &Core::Cryptography::scReduce32);
    function("hashToScalar", &Core::Cryptography::hashToScalar);
}
