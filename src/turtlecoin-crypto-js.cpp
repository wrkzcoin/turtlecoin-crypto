// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include <stdio.h>

#include <stdlib.h>

#include <turtlecoin-crypto.h>

#include <emscripten/bind.h>

using namespace emscripten;

struct Keys
{
  std::string PublicKey;
  std::string SecretKey;
};

/* Most of the redefintions below are the result of either emscripten not
   handling std::tuple or issues with method signatures having a uint64_t */

std::string cn_soft_shell_slow_hash_v0(const std::string data, const int height)
{
    return Core::Cryptography::cn_soft_shell_slow_hash_v0(data, height);
}

std::string cn_soft_shell_slow_hash_v1(const std::string data, const int height)
{
    return Core::Cryptography::cn_soft_shell_slow_hash_v1(data, height);
}

std::string cn_soft_shell_slow_hash_v2(const std::string data, const int height)
{
    return Core::Cryptography::cn_soft_shell_slow_hash_v2(data, height);
}

std::vector<std::string> generateRingSignatures(
    const std::string prefixHash,
    const std::string keyImage,
    const std::vector<std::string> publicKeys,
    const std::string transactionSecretKey,
    const int realOutputIndex
)
{
    const auto [success, signatures] = Core::Cryptography::generateRingSignatures(
        prefixHash,
        keyImage,
        publicKeys,
        transactionSecretKey,
        realOutputIndex
    );

    return signatures;
}

Keys generateViewKeysFromPrivateSpendKey(const std::string secretKey)
{
    const auto [viewSecretKey, viewPublicKey] = Core::Cryptography::generateViewKeysFromPrivateSpendKey(secretKey);

    Keys keys;

    keys.PublicKey = viewPublicKey;

    keys.SecretKey = viewSecretKey;

    return keys;
}

Keys generateKeys()
{
    const auto [secretKey, publicKey] = Core::Cryptography::generateKeys();

    Keys keys;

    keys.PublicKey = publicKey;

    keys.SecretKey = secretKey;

    return keys;
}

std::string secretKeyToPublicKey(const std::string secretKey)
{
    const auto [success, publicKey] = Core::Cryptography::secretKeyToPublicKey(secretKey);

    return publicKey;
}

std::string generateKeyDerivation(const std::string publicKey, const std::string secretKey)
{
    const auto [success, derivation] = Core::Cryptography::generateKeyDerivation(publicKey, secretKey);

    return derivation;
}

std::string derivePublicKey(const std::string derivation, const int outputIndex, const std::string publicKey)
{
    const auto [success, derivedKey] = Core::Cryptography::derivePublicKey(derivation, outputIndex, publicKey);

    return derivedKey;
}

std::string deriveSecretKey(const std::string derivation, const int outputIndex, const std::string secretKey)
{
    return Core::Cryptography::deriveSecretKey(derivation, outputIndex, secretKey);
}

std::string underivePublicKey(const std::string derivation, const int outputIndex, const std::string derivedKey)
{
    const auto [success, publicKey] = Core::Cryptography::underivePublicKey(derivation, outputIndex, derivedKey);

    return publicKey;
}

EMSCRIPTEN_BINDINGS(signatures)
{
    function("cn_fast_hash", &Core::Cryptography::cn_fast_hash);

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

    function("cn_soft_shell_slow_hash_v0", &cn_soft_shell_slow_hash_v0);
    function("cn_soft_shell_slow_hash_v1", &cn_soft_shell_slow_hash_v1);
    function("cn_soft_shell_slow_hash_v2", &cn_soft_shell_slow_hash_v2);

    function("chukwa_slow_hash", &Core::Cryptography::chukwa_slow_hash);

    function("tree_hash", &Core::Cryptography::tree_hash);
    function("tree_branch", &Core::Cryptography::tree_branch);
    function("tree_hash_from_branch", &Core::Cryptography::tree_hash_from_branch);

    function("generateRingSignatures", &generateRingSignatures);
    function("checkRingSignature", &Core::Cryptography::checkRingSignature);
    function("generatePrivateViewKeyFromPrivateSpendKey", &Core::Cryptography::generatePrivateViewKeyFromPrivateSpendKey);
    function("generateViewKeysFromPrivateSpendKey", &generateViewKeysFromPrivateSpendKey);
    function("generateKeys", &generateKeys);
    function("checkKey", &Core::Cryptography::checkKey);
    function("secretKeyToPublicKey", &secretKeyToPublicKey);
    function("generateKeyDerivation", &generateKeyDerivation);
    function("derivePublicKey", &derivePublicKey);
    function("deriveSecretKey", &deriveSecretKey);
    function("underivePublicKey", &underivePublicKey);
    function("generateSignature", &Core::Cryptography::generateSignature);
    function("checkSignature", &Core::Cryptography::checkSignature);
    function("generateKeyImage", &Core::Cryptography::generateKeyImage);
    function("scalarmultKey", &Core::Cryptography::scalarmultKey);
    function("hashToEllipticCurve", &Core::Cryptography::hashToEllipticCurve);
    function("scReduce32", &Core::Cryptography::scReduce32);
    function("hashToScalar", &Core::Cryptography::hashToScalar);

    register_vector<std::string>("VectorString");

    value_object<Keys>("Keys")
        .field("SecretKey", &Keys::SecretKey)
        .field("PublicKey", &Keys::PublicKey);
}
