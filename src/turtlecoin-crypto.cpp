// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

#include <turtlecoin-crypto.h>

#include <StringTools.h>

#ifdef _WIN32
# include <windows.h>
# ifdef _MANAGED
#   pragma managed(push, off)
# endif

EXPORTDLL bool DllMain(
    HMODULE		/*hModule*/,
    DWORD		ul_reason_for_call,
    LPVOID		/*lpReserved*/
)
{
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return true;
}

# ifdef _MANAGED
#   pragma managed(pop)
# endif
#endif

namespace CryptoCore
{
    inline Crypto::BinaryArray toBinaryArray(const std::string input)
    {
        return Common::fromHex(input);
    }

    /* Hashing Methods */
    std::string TurtleCoin::cn_fast_hash(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_fast_hash(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string TurtleCoin::cn_slow_hash_v0(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_slow_hash_v0(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string TurtleCoin::cn_slow_hash_v1(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_slow_hash_v1(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string TurtleCoin::cn_slow_hash_v2(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_slow_hash_v2(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string TurtleCoin::cn_lite_slow_hash_v0(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_lite_slow_hash_v0(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string TurtleCoin::cn_lite_slow_hash_v1(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_lite_slow_hash_v1(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string TurtleCoin::cn_lite_slow_hash_v2(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_lite_slow_hash_v2(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string TurtleCoin::cn_dark_slow_hash_v0(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_dark_slow_hash_v0(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string TurtleCoin::cn_dark_slow_hash_v1(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_dark_slow_hash_v1(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string TurtleCoin::cn_dark_slow_hash_v2(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_dark_slow_hash_v2(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string TurtleCoin::cn_dark_lite_slow_hash_v0(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_dark_lite_slow_hash_v0(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string TurtleCoin::cn_dark_lite_slow_hash_v1(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_dark_lite_slow_hash_v1(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string TurtleCoin::cn_dark_lite_slow_hash_v2(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_dark_lite_slow_hash_v2(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string TurtleCoin::cn_turtle_slow_hash_v0(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_turtle_slow_hash_v0(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string TurtleCoin::cn_turtle_slow_hash_v1(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_turtle_slow_hash_v1(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string TurtleCoin::cn_turtle_slow_hash_v2(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_turtle_slow_hash_v2(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string TurtleCoin::cn_turtle_lite_slow_hash_v0(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_turtle_lite_slow_hash_v0(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string TurtleCoin::cn_turtle_lite_slow_hash_v1(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_turtle_lite_slow_hash_v1(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string TurtleCoin::cn_turtle_lite_slow_hash_v2(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_turtle_lite_slow_hash_v2(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string TurtleCoin::cn_soft_shell_slow_hash_v0(const std::string input, const uint32_t height)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_soft_shell_slow_hash_v0(data.data(), data.size(), hash, height);

        return Common::podToHex(hash);
    }

    std::string TurtleCoin::cn_soft_shell_slow_hash_v1(const std::string input, const uint32_t height)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_soft_shell_slow_hash_v1(data.data(), data.size(), hash, height);

        return Common::podToHex(hash);
    }

    std::string TurtleCoin::cn_soft_shell_slow_hash_v2(const std::string input, const uint32_t height)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::cn_soft_shell_slow_hash_v2(data.data(), data.size(), hash, height);

        return Common::podToHex(hash);
    }

    std::string TurtleCoin::chukwa_slow_hash(const std::string input)
    {
        Crypto::Hash hash = Crypto::Hash();

        Crypto::BinaryArray data = toBinaryArray(input);

        Crypto::chukwa_slow_hash(data.data(), data.size(), hash);

        return Common::podToHex(hash);
    }

    std::string TurtleCoin::tree_hash(const std::vector<std::string> hashes)
    {
        std::vector<Crypto::Hash> treeHashes;

        for (const auto hash : hashes)
        {
            Crypto::Hash tempHash = Crypto::Hash();

            Common::podFromHex(hash, tempHash);

            treeHashes.push_back(tempHash);
        }

        Crypto::Hash treeHash = Crypto::Hash();

        Crypto::tree_hash(treeHashes.data(), treeHashes.size(), treeHash);

        return Common::podToHex(treeHash);
    }

    std::vector<std::string> TurtleCoin::tree_branch(const std::vector<std::string> hashes)
    {
        std::vector<Crypto::Hash> _hashes;

        for (const auto hash : hashes)
        {
            Crypto::Hash tempHash = Crypto::Hash();

            Common::podFromHex(hash, tempHash);

            _hashes.push_back(tempHash);
        }

        std::vector<Crypto::Hash> _branch;

        Crypto::tree_branch(_hashes.data(), _hashes.size(), _branch.data());

        std::vector<std::string> branch;

        for (const auto hash : _branch)
        {
            branch.push_back(Common::podToHex(hash));
        }

        return branch;
    }

    std::string TurtleCoin::tree_hash_from_branch(const std::vector<std::string> branches, const size_t depth, const std::string leaf, const std::string path)
    {
        std::vector<Crypto::Hash> _branches;

        for (const auto branch : branches)
        {
            Crypto::Hash _branch = Crypto::Hash();

            Common::podFromHex(branch, _branch);

            _branches.push_back(_branch);
        }

        Crypto::Hash _leaf = Crypto::Hash();

        Common::podFromHex(leaf, _leaf);

        Crypto::Hash _path = Crypto::Hash();

        Common::podFromHex(path, _path);

        Crypto::Hash _hash = Crypto::Hash();

        Crypto::tree_hash_from_branch(_branches.data(), depth, _leaf, _path.data, _hash);

        return Common::podToHex(_hash);
    }

    /* Crypto Methods */
    std::tuple<bool, std::vector<std::string>> TurtleCoin::generateRingSignatures(
        const std::string prefixHash,
        const std::string keyImage,
        const std::vector<std::string> publicKeys,
        const std::string transactionSecretKey,
        const uint64_t realOutputIndex
    )
    {
        Crypto::Hash _prefixHash = Crypto::Hash();

        Common::podFromHex(prefixHash, _prefixHash);

        Crypto::KeyImage _keyImage = Crypto::KeyImage();

        Common::podFromHex(keyImage, _keyImage);

        std::vector<Crypto::PublicKey> _publicKeys;

        for (const auto publicKey : publicKeys)
        {
            Crypto::PublicKey _publicKey = Crypto::PublicKey();

            Common::podFromHex(publicKey, _publicKey);

            _publicKeys.push_back(_publicKey);
        }

        Crypto::SecretKey _transactionSecretKey;

        Common::podFromHex(transactionSecretKey, _transactionSecretKey);

        const auto [success, _signatures] = Crypto::crypto_ops::generateRingSignatures(
            _prefixHash,
            _keyImage,
            _publicKeys,
            _transactionSecretKey,
            realOutputIndex
        );

        std::vector<std::string> signatures;

        if (success)
        {
            for (const auto signature : _signatures)
            {
                signatures.push_back(Common::toHex(&signature, sizeof(signature)));
            }
        }

        return {success, signatures};
    }

    bool TurtleCoin::checkRingSignature(
        const std::string prefixHash,
        const std::string keyImage,
        const std::vector<std::string> publicKeys,
        const std::vector<std::string> signatures
    )
    {
        Crypto::Hash _prefixHash = Crypto::Hash();

        Common::podFromHex(prefixHash, _prefixHash);

        Crypto::KeyImage _keyImage = Crypto::KeyImage();

        Common::podFromHex(keyImage, _keyImage);

        std::vector<Crypto::PublicKey> _publicKeys;

        for (const auto publicKey : publicKeys)
        {
            Crypto::PublicKey _publicKey = Crypto::PublicKey();

            Common::podFromHex(publicKey, _publicKey);

            _publicKeys.push_back(_publicKey);
        }

        std::vector<Crypto::Signature> _signatures;

        for (const auto signature : signatures)
        {
            Crypto::Signature _signature = Crypto::Signature();

            Common::podFromHex(signature, _signature);

            _signatures.push_back(_signature);
        }

        return Crypto::crypto_ops::checkRingSignature(
            _prefixHash,
            _keyImage,
            _publicKeys,
            _signatures
        );
    }

    std::string TurtleCoin::generatePrivateViewKeyFromPrivateSpendKey(const std::string privateSpendKey)
    {
        Crypto::SecretKey _privateSpendKey = Crypto::SecretKey();

        Common::podFromHex(privateSpendKey, _privateSpendKey);

        Crypto::SecretKey privateViewKey = Crypto::SecretKey();

        Crypto::crypto_ops::generateViewFromSpend(_privateSpendKey, privateViewKey);

        return Common::podToHex(privateViewKey);
    }

    std::tuple<std::string, std::string> TurtleCoin::generateViewKeysFromPrivateSpendKey(const std::string privateSpendKey)
    {
        Crypto::SecretKey _privateSpendKey = Crypto::SecretKey();

        Common::podFromHex(privateSpendKey, _privateSpendKey);

        Crypto::SecretKey _privateViewKey = Crypto::SecretKey();

        Crypto::PublicKey _publicViewKey = Crypto::PublicKey();

        Crypto::crypto_ops::generateViewFromSpend(_privateSpendKey, _privateViewKey, _publicViewKey);

        std::string privateViewKey = Common::podToHex(_privateViewKey);

        std::string publicViewKey = Common::podToHex(_publicViewKey);

        return {privateViewKey, publicViewKey};
    }

    std::tuple<std::string, std::string> TurtleCoin::generateKeys()
    {
        Crypto::SecretKey _privateKey = Crypto::SecretKey();

        Crypto::PublicKey _publicKey = Crypto::PublicKey();

        Crypto::generate_keys(_publicKey, _privateKey);

        std::string privateKey = Common::podToHex(_privateKey);

        std::string publicKey = Common::podToHex(_publicKey);

        return {privateKey, publicKey};
    }

    bool TurtleCoin::checkKey(const std::string publicKey)
    {
        Crypto::PublicKey _publicKey = Crypto::PublicKey();

        Common::podFromHex(publicKey, _publicKey);

        return Crypto::check_key(_publicKey);
    }

    std::tuple<bool, std::string> TurtleCoin::secretKeyToPublicKey(const std::string privateKey)
    {
        Crypto::SecretKey _privateKey = Crypto::SecretKey();

        Common::podFromHex(privateKey, _privateKey);

        Crypto::PublicKey _publicKey = Crypto::PublicKey();

        const auto success = Crypto::secret_key_to_public_key(_privateKey, _publicKey);

        std::string publicKey;

        if (success)
        {
            publicKey = Common::podToHex(_publicKey);
        }

        return {success, publicKey};
    }

    std::tuple<bool, std::string> TurtleCoin::generateKeyDerivation(const std::string publicKey, const std::string privateKey)
    {
        Crypto::PublicKey _publicKey = Crypto::PublicKey();

        Common::podFromHex(publicKey, _publicKey);

        Crypto::SecretKey _privateKey = Crypto::SecretKey();

        Common::podFromHex(privateKey, _privateKey);

        Crypto::KeyDerivation _derivation = Crypto::KeyDerivation();

        const auto success = Crypto::generate_key_derivation(_publicKey, _privateKey, _derivation);

        std::string derivation;

        if (success)
        {
            derivation = Common::podToHex(_derivation);
        }

        return {success, derivation};
    }

    std::tuple<bool, std::string> TurtleCoin::derivePublicKey(const std::string derivation, const size_t outputIndex, const std::string publicKey)
    {
        Crypto::KeyDerivation _derivation = Crypto::KeyDerivation();

        Common::podFromHex(derivation, _derivation);

        Crypto::PublicKey _publicKey = Crypto::PublicKey();

        Common::podFromHex(publicKey, _publicKey);

        Crypto::PublicKey _derivedKey = Crypto::PublicKey();

        const auto success = Crypto::derive_public_key(_derivation, outputIndex, _publicKey, _derivedKey);

        std::string derivedKey;

        if (success)
        {
            derivedKey = Common::podToHex(_derivedKey);
        }

        return {success, derivedKey};
    }

    std::string TurtleCoin::deriveSecretKey(const std::string derivation, const size_t outputIndex, const std::string privateKey)
    {
        Crypto::KeyDerivation _derivation = Crypto::KeyDerivation();

        Common::podFromHex(derivation, _derivation);

        Crypto::SecretKey _privateKey = Crypto::SecretKey();

        Common::podFromHex(privateKey, _privateKey);

        Crypto::SecretKey _derivedKey = Crypto::SecretKey();

        Crypto::derive_secret_key(_derivation, outputIndex, _privateKey, _derivedKey);

        return Common::podToHex(_derivedKey);
    }

    std::tuple<bool, std::string> TurtleCoin::underivePublicKey(const std::string derivation, const size_t outputIndex, const std::string publicKey)
    {
        Crypto::KeyDerivation _derivation = Crypto::KeyDerivation();

        Common::podFromHex(derivation, _derivation);

        Crypto::PublicKey _publicKey = Crypto::PublicKey();

        Common::podFromHex(publicKey, _publicKey);

        Crypto::PublicKey _derivedKey = Crypto::PublicKey();

        const auto success = Crypto::underive_public_key(_derivation, outputIndex, _publicKey, _derivedKey);

        std::string derivedKey;

        if (success)
        {
            derivedKey = Common::podToHex(_derivedKey);
        }

        return {success, derivedKey};
    }

    std::string TurtleCoin::generateSignature(const std::string prefixHash, const std::string publicKey, const std::string privateKey)
    {
        Crypto::Hash _prefixHash = Crypto::Hash();

        Common::podFromHex(prefixHash, _prefixHash);

        Crypto::PublicKey _publicKey = Crypto::PublicKey();

        Common::podFromHex(publicKey, _publicKey);

        Crypto::SecretKey _privateKey = Crypto::SecretKey();

        Common::podFromHex(privateKey, _privateKey);

        Crypto::Signature _signature = Crypto::Signature();

        Crypto::generate_signature(_prefixHash, _publicKey, _privateKey, _signature);

        return Common::podToHex(_signature);
    }

    bool TurtleCoin::checkSignature(const std::string prefixHash, const std::string publicKey, const std::string signature)
    {
        Crypto::Hash _prefixHash = Crypto::Hash();

        Common::podFromHex(prefixHash, _prefixHash);

        Crypto::PublicKey _publicKey = Crypto::PublicKey();

        Common::podFromHex(publicKey, _publicKey);

        Crypto::Signature _signature = Crypto::Signature();

        Common::podFromHex(signature, _signature);

        return Crypto::check_signature(_prefixHash, _publicKey, _signature);
    }

    std::string TurtleCoin::generateKeyImage(const std::string publicKey, const std::string privateKey)
    {
        Crypto::PublicKey _publicKey = Crypto::PublicKey();

        Common::podFromHex(publicKey, _publicKey);

        Crypto::SecretKey _privateKey = Crypto::SecretKey();

        Common::podFromHex(privateKey, _privateKey);

        Crypto::KeyImage _keyImage = Crypto::KeyImage();

        Crypto::generate_key_image(_publicKey, _privateKey, _keyImage);

        return Common::podToHex(_keyImage);
    }

    std::string TurtleCoin::scalarmultKey(const std::string keyImageA, const std::string keyImageB)
    {
        Crypto::KeyImage _keyImageA = Crypto::KeyImage();

        Common::podFromHex(keyImageA, _keyImageA);

        Crypto::KeyImage _keyImageB = Crypto::KeyImage();

        Common::podFromHex(keyImageB, _keyImageB);

        Crypto::KeyImage _keyImage = Crypto::scalarmultKey(_keyImageA, _keyImageB);

        return Common::podToHex(_keyImage);
    }

    std::string TurtleCoin::hashToEllipticCurve(const std::string hash)
    {
        Crypto::Hash _hash = Crypto::Hash();

        Common::podFromHex(hash, _hash);

        Crypto::PublicKey _ellipticCurve = Crypto::PublicKey();

        Crypto::hash_data_to_ec(_hash.data, sizeof(_hash.data), _ellipticCurve);

        return Common::podToHex(_ellipticCurve);
    }
}