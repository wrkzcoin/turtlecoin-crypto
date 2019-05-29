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
    class EXPORTDLL Cryptography
    {
        public:
            /* Hashing Methods */
            static std::string cn_fast_hash(const std::string);

            static std::string cn_slow_hash_v0(const std::string);
            static std::string cn_slow_hash_v1(const std::string);
            static std::string cn_slow_hash_v2(const std::string);

            static std::string cn_lite_slow_hash_v0(const std::string);
            static std::string cn_lite_slow_hash_v1(const std::string);
            static std::string cn_lite_slow_hash_v2(const std::string);

            static std::string cn_dark_slow_hash_v0(const std::string);
            static std::string cn_dark_slow_hash_v1(const std::string);
            static std::string cn_dark_slow_hash_v2(const std::string);

            static std::string cn_dark_lite_slow_hash_v0(const std::string);
            static std::string cn_dark_lite_slow_hash_v1(const std::string);
            static std::string cn_dark_lite_slow_hash_v2(const std::string);

            static std::string cn_turtle_slow_hash_v0(const std::string);
            static std::string cn_turtle_slow_hash_v1(const std::string);
            static std::string cn_turtle_slow_hash_v2(const std::string);

            static std::string cn_turtle_lite_slow_hash_v0(const std::string);
            static std::string cn_turtle_lite_slow_hash_v1(const std::string);
            static std::string cn_turtle_lite_slow_hash_v2(const std::string);

            static std::string cn_soft_shell_slow_hash_v0(const std::string, const uint32_t);
            static std::string cn_soft_shell_slow_hash_v1(const std::string, const uint32_t);
            static std::string cn_soft_shell_slow_hash_v2(const std::string, const uint32_t);

            static std::string chukwa_slow_hash(const std::string);

            static std::string tree_hash(const std::vector<std::string>);
            static std::vector<std::string> tree_branch(const std::vector<std::string>);
            static std::string tree_hash_from_branch(const std::vector<std::string>, const size_t depth, const std::string, const std::string);

            /* Crypto Methods */
            static std::tuple<bool, std::vector<std::string>> generateRingSignatures(
                const std::string,
                const std::string,
                const std::vector<std::string>,
                const std::string,
                const uint64_t
            );
            static bool checkRingSignature(
                const std::string, 
                const std::string, 
                const std::vector<std::string>, 
                const std::vector<std::string>
            );
            static std::string generatePrivateViewKeyFromPrivateSpendKey(const std::string);
            static std::tuple<std::string, std::string> generateViewKeysFromPrivateSpendKey(const std::string);
            static std::tuple<std::string, std::string> generateKeys();
            static bool checkKey(const std::string);
            static std::tuple<bool, std::string> secretKeyToPublicKey(const std::string);
            static std::tuple<bool, std::string> generateKeyDerivation(const std::string, const std::string);
            static std::tuple<bool, std::string> derivePublicKey(const std::string, const size_t, const std::string);
            static std::string deriveSecretKey(const std::string, const size_t, const std::string);
            static std::tuple<bool, std::string> underivePublicKey(const std::string, const size_t, const std::string);
            static std::string generateSignature(const std::string, const std::string, const std::string);
            static bool checkSignature(const std::string, const std::string, const std::string);
            static std::string generateKeyImage(const std::string, const std::string);
            static std::string scalarmultKey(const std::string, const std::string);
            static std::string hashToEllipticCurve(const std::string);
    };
}

#ifdef __cplusplus
}
#endif