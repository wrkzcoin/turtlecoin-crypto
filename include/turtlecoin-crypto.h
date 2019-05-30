// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#pragma once

#ifndef NO_CRYPTO_EXPORTS
# ifdef _WIN32
#      ifdef CRYPTO_EXPORTS
#         define EXPORTDLL __declspec(dllexport)
#      else
#         define EXPORTDLL __declspec(dllimport)
#      endif
# else
#   define EXPORTDLL
# endif
#else
# define EXPORTDLL
#endif

#include <crypto.h>

#ifdef __cplusplus
extern "C" {
#endif

namespace Core
{
    class Cryptography
    {
        public:
            /* Hashing Methods */
            static std::string cn_fast_hash(const std::string data);

            static std::string cn_slow_hash_v0(const std::string data);
            static std::string cn_slow_hash_v1(const std::string data);
            static std::string cn_slow_hash_v2(const std::string data);

            static std::string cn_lite_slow_hash_v0(const std::string data);
            static std::string cn_lite_slow_hash_v1(const std::string data);
            static std::string cn_lite_slow_hash_v2(const std::string data);

            static std::string cn_dark_slow_hash_v0(const std::string data);
            static std::string cn_dark_slow_hash_v1(const std::string data);
            static std::string cn_dark_slow_hash_v2(const std::string data);

            static std::string cn_dark_lite_slow_hash_v0(const std::string data);
            static std::string cn_dark_lite_slow_hash_v1(const std::string data);
            static std::string cn_dark_lite_slow_hash_v2(const std::string data);

            static std::string cn_turtle_slow_hash_v0(const std::string data);
            static std::string cn_turtle_slow_hash_v1(const std::string data);
            static std::string cn_turtle_slow_hash_v2(const std::string data);

            static std::string cn_turtle_lite_slow_hash_v0(const std::string data);
            static std::string cn_turtle_lite_slow_hash_v1(const std::string data);
            static std::string cn_turtle_lite_slow_hash_v2(const std::string data);

            static std::string cn_soft_shell_slow_hash_v0(const std::string data, const uint32_t height);
            static std::string cn_soft_shell_slow_hash_v1(const std::string data, const uint32_t height);
            static std::string cn_soft_shell_slow_hash_v2(const std::string data, const uint32_t height);

            static std::string chukwa_slow_hash(const std::string data);

            static std::string tree_hash(const std::vector<std::string> hashes);
            static std::vector<std::string> tree_branch(const std::vector<std::string> hashes);
            static std::string tree_hash_from_branch(const std::vector<std::string> branches, const size_t depth, const std::string leaf, const std::string path);

            /* Crypto Methods */
            static std::tuple<bool, std::vector<std::string>> generateRingSignatures(
                const std::string prefixHash,
                const std::string keyImage,
                const std::vector<std::string> publicKeys,
                const std::string transactionSecretKey,
                const uint64_t realOutputIndex
            );
            static bool checkRingSignature(
                const std::string prefixHash,
                const std::string keyImage,
                const std::vector<std::string> publicKeys,
                const std::vector<std::string> signatures
            );
            static std::string generatePrivateViewKeyFromPrivateSpendKey(const std::string secretKey);
            static std::tuple<std::string, std::string> generateViewKeysFromPrivateSpendKey(const std::string secretKey);
            static std::tuple<std::string, std::string> generateKeys();
            static bool checkKey(const std::string publicKey);
            static std::tuple<bool, std::string> secretKeyToPublicKey(const std::string secretKey);
            static std::tuple<bool, std::string> generateKeyDerivation(const std::string publicKey, const std::string secretKey);
            static std::tuple<bool, std::string> derivePublicKey(const std::string derivation, const size_t outputIndex, const std::string publicKey);
            static std::string deriveSecretKey(const std::string derivation, const size_t outputIndex, const std::string secretKey);
            static std::tuple<bool, std::string> underivePublicKey(const std::string derivation, const size_t outputIndex, const std::string derivedPublicKey);
            static std::string generateSignature(const std::string prefixHash, const std::string publicKey, const std::string secretKey);
            static bool checkSignature(const std::string prefixHash, const std::string publicKey, const std::string signature);
            static std::string generateKeyImage(const std::string publicKey, const std::string secretKey);
            static std::string scalarmultKey(const std::string keyImageA, const std::string keyImageB);
            static std::string hashToEllipticCurve(const std::string hash);
            static std::string scReduce32(const std::string data);
            static std::string hashToScalar(const std::string hash);
    };
}

#ifdef __cplusplus
}
#endif