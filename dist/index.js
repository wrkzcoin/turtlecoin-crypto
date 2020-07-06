"use strict";
// Copyright (c) 2020, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Crypto = void 0;
const js_sha3_1 = require("js-sha3");
/**
 * @ignore
 */
const userCryptoFunctions = {};
/**
 * @ignore
 */
var Types;
(function (Types) {
    Types[Types["UNKNOWN"] = 0] = "UNKNOWN";
    Types[Types["NODEADDON"] = 1] = "NODEADDON";
    Types[Types["WASM"] = 2] = "WASM";
    Types[Types["WASMJS"] = 3] = "WASMJS";
    Types[Types["JS"] = 4] = "JS";
    Types[Types["MIXED"] = 5] = "MIXED";
})(Types || (Types = {}));
/**
 * @ignore
 */
const moduleVars = {
    crypto: null,
    type: Types.UNKNOWN
};
/**
 * @ignore
 */
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
// eslint-disable-next-line no-extend-native
Array.prototype.toVectorString = function () {
    if (!moduleVars.crypto.VectorString) {
        throw new Error('VectorString unavailable');
    }
    const arr = new moduleVars.crypto.VectorString();
    this.forEach((key) => arr.push_back(key));
    return arr;
};
/**
 * A class containing the TurtleCoin cryptographic primitive methods that wraps
 * the Node.js native module, the WASM binary, or native JS implementations
 * into a common interface
 */
class Crypto {
    /**
     * Returns the type of the cryptographic primitives used by the wrapper
     */
    static get type() {
        switch (moduleVars.type) {
            case Types.NODEADDON:
                return 'c++';
            case Types.WASM:
                return 'wasm';
            case Types.WASMJS:
                return 'wasmjs';
            case Types.JS:
                return 'js';
            default:
                return 'unknown';
        }
    }
    /**
     * Returns if the Node.js native library is being used
     */
    static get isNative() {
        switch (moduleVars.type) {
            case Types.NODEADDON:
                return false;
            default:
                return true;
        }
    }
    /**
     * Returns if the wrapper is loaded and ready
     */
    static get isReady() {
        return (moduleVars.crypto !== null && typeof moduleVars.crypto.cn_fast_hash === 'function');
    }
    /**
     * Retrieves the array of user-defined cryptographic primitive functions
     * that replace our primitives at runtime
     */
    static get userCryptoFunctions() {
        return userCryptoFunctions;
    }
    /**
     * Allows for updating the user-defined cryptographic primitive functions
     * that will replace our primitives at runtime.
     * @param config
     */
    static set userCryptoFunctions(config) {
        if (config && typeof config === 'object') {
            Object.keys(config).forEach((key) => {
                if (typeof config[key] === 'function') {
                    userCryptoFunctions[key] = config[key];
                }
            });
        }
    }
    /**
     * Forces the wrapper to use the JS (slow) cryptographic primitives
     */
    static forceJSCrypto() {
        return loadNativeJS();
    }
    /**
     * Creates a new wrapper object
     * @param [config] may contain user-defined cryptographic primitive functions
     * that will replace our primitives at runtime.
     */
    constructor(config) {
        if (!initialize()) {
            throw new Error('Could not initialize underlying cryptographic library');
        }
        if (config && typeof config === 'object') {
            Object.keys(config).forEach((key) => {
                if (typeof config[key] === 'function') {
                    userCryptoFunctions[key] = config[key];
                    moduleVars.type = Types.MIXED;
                }
            });
        }
    }
    /**
     * Returns the type of the cryptographic primitives used by the wrapper
     */
    get type() {
        return Crypto.type;
    }
    /**
     * Returns if the Node.js native library is being used
     */
    get isNative() {
        return Crypto.isNative;
    }
    /**
     * Returns if the wrapper is loaded and ready
     */
    get isReady() {
        return Crypto.isReady;
    }
    /**
     * Retrieves the array of user-defined cryptographic primitive functions
     * that replace our primitives at runtime
     */
    get userCryptoFunctions() {
        return Crypto.userCryptoFunctions;
    }
    /**
     * Allows for updating the user-defined cryptographic primitive functions
     * that will replace our primitives at runtime.
     * @param config
     */
    set userCryptoFunctions(config) {
        Crypto.userCryptoFunctions = config;
    }
    /**
     * Forces the wrapper to use the JS (slow) cryptographic primitives
     */
    forceJSCrypto() {
        return Crypto.forceJSCrypto();
    }
    /**
     * Calculates the multisignature (m) private keys using our private spend key
     * and the public spend keys of other participants in a M:N scheme
     * @param privateSpendKey our private spend key
     * @param publicKeys an array of the other participants public spend keys
     */
    calculateMultisigPrivateKeys(privateSpendKey, publicKeys) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!(yield this.checkScalar(privateSpendKey))) {
                throw new Error('privateSpendKey is not a scalar');
            }
            if (!Array.isArray(publicKeys)) {
                throw new Error('publicKeys must be an array');
            }
            publicKeys.forEach((key) => {
                if (!this.checkKey(key)) {
                    throw new Error('Invalid public key found');
                }
            });
            return tryRunFunc('calculateMultisigPrivateKeys', privateSpendKey, publicKeys);
        });
    }
    /**
     * Calculates a shared private key from the private keys supplied
     * @param privateKeys the array of private keys
     */
    calculateSharedPrivateKey(privateKeys) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!Array.isArray(privateKeys)) {
                throw new Error('privateKeys must be an array');
            }
            privateKeys.forEach((key) => {
                if (!this.checkScalar(key)) {
                    throw new Error('Invalid private key found');
                }
            });
            return tryRunFunc('calculateSharedPrivateKey', privateKeys);
        });
    }
    /**
     * Calculates a shared public key from the public keys supplied
     * @param publicKeys the array of public keys
     */
    calculateSharedPublicKey(publicKeys) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!Array.isArray(publicKeys)) {
                throw new Error('publicKeys must be an array');
            }
            publicKeys.forEach((key) => {
                if (!this.checkKey(key)) {
                    throw new Error('Invalid public key found');
                }
            });
            return tryRunFunc('calculateSharedPublicKey', publicKeys);
        });
    }
    /**
     * Checks whether a given key is a public key
     * @param key the public key to check
     */
    checkKey(key) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex64(key)) {
                return false;
            }
            return tryRunFunc('checkKey', key);
        });
    }
    /**
     * Checks a set of ring signatures to verify that they are valid
     * @param hash the hash (often the transaction prefix hash)
     * @param keyImage real keyImage used to generate the signatures
     * @param inputKeys the output keys used during signing (mixins + real)
     * @param signatures the signatures
     */
    checkRingSignature(hash, keyImage, inputKeys, signatures) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.checkRingSignatures(hash, keyImage, inputKeys, signatures);
        });
    }
    /**
     * Checks a set of ring signatures to verify that they are valid
     * @param hash the hash (often the transaction prefix hash)
     * @param keyImage real keyImage used to generate the signatures
     * @param inputKeys the output keys used during signing (mixins + real)
     * @param signatures the signatures
     */
    checkRingSignatures(hash, keyImage, inputKeys, signatures) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex64(hash)) {
                return false;
            }
            if (!isHex64(keyImage)) {
                return false;
            }
            if (!Array.isArray(inputKeys)) {
                return false;
            }
            if (!Array.isArray(signatures)) {
                return false;
            }
            let err = false;
            inputKeys.forEach((key) => {
                if (!this.checkKey(key)) {
                    err = true;
                }
            });
            signatures.forEach((sig) => {
                if (!isHex128(sig)) {
                    err = true;
                }
            });
            if (err) {
                return false;
            }
            return tryRunFunc('checkRingSignature', hash, keyImage, inputKeys, signatures);
        });
    }
    /**
     * Checks whether the given key is a private key
     * @param privateKey
     */
    checkScalar(privateKey) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex64(privateKey)) {
                return false;
            }
            return (privateKey === (yield this.scReduce32(privateKey)));
        });
    }
    /**
     * Checks that the given signature is valid for the hash and public key supplied
     * @param hash the hash (message digest) used
     * @param publicKey the public key of the private key used to sign
     * @param signature the signature
     */
    checkSignature(hash, publicKey, signature) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex64(hash)) {
                return false;
            }
            if (!(yield this.checkKey(publicKey))) {
                return false;
            }
            if (!isHex128(signature)) {
                return false;
            }
            return tryRunFunc('checkSignature', hash, publicKey, signature);
        });
    }
    /**
     * Calculates the hash of the data supplied using the cn_fast_hash method
     * @param data
     */
    cn_fast_hash(data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Supplied data must be in hexadecimal form');
            }
            try {
                return tryRunFunc('cn_fast_hash', data);
            }
            catch (e) {
                return js_sha3_1.keccak256(Buffer.from(data, 'hex'));
            }
        });
    }
    /**
     * Completes a given set of prepared ring signatures using the single
     * privateEphemeral
     * @param privateEphemeral private ephemeral of the output being spent
     * @param realIndex the position of the signature in the array that belongs
     * to the real output being spent
     * @param k the random scalar provided with the prepared ring signatures
     * @param signatures the prepared ring signatures
     */
    completeRingSignatures(privateEphemeral, realIndex, k, signatures) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!(yield this.checkScalar(privateEphemeral))) {
                throw new Error('Invalid private key found');
            }
            if (!Array.isArray(signatures)) {
                throw new Error('signatures must be an array');
            }
            if (!isUInt(realIndex) || realIndex > signatures.length - 1) {
                throw new Error('Invalid realIndex format');
            }
            if (!(yield this.checkScalar(k))) {
                throw new Error('Invalid k found');
            }
            signatures.forEach((sig) => {
                if (!isHex128(sig)) {
                    throw new Error('Invalid signature found');
                }
            });
            return tryRunFunc('completeRingSignatures', privateEphemeral, realIndex, k, signatures);
        });
    }
    /**
     * Converts a key derivation to its resulting scalar
     * @param derivation the key derivation
     * @param outputIndex the index of the output in the transaction
     */
    derivationToScalar(derivation, outputIndex) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex64(derivation)) {
                throw new Error('Invalid derivation found');
            }
            if (!isUInt(outputIndex)) {
                throw new Error('Invalid output index found');
            }
            return tryRunFunc('derivationToScalar', derivation, outputIndex);
        });
    }
    /**
     * Derives the public ephemeral from the key derivation, output index, and
     * our public spend key
     * @param derivation the key derivation
     * @param outputIndex the index of the output in the transaction
     * @param publicKey our public spend key
     */
    derivePublicKey(derivation, outputIndex, publicKey) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex64(derivation)) {
                throw new Error('Invalid derivation found');
            }
            if (!isUInt(outputIndex)) {
                throw new Error('Invalid output index found');
            }
            if (!(yield this.checkKey(publicKey))) {
                throw new Error('Invalid public key found');
            }
            return tryRunFunc('derivePublicKey', derivation, outputIndex, publicKey);
        });
    }
    /**
     * Derives the private ephemeral from the key derivation, output index, and
     * our private spend key
     * @param derivation the key derivation
     * @param outputIndex the index of the output in the transaction
     * @param privateKey our private spend key
     */
    deriveSecretKey(derivation, outputIndex, privateKey) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex64(derivation)) {
                throw new Error('Invalid derivation found');
            }
            if (!isUInt(outputIndex)) {
                throw new Error('Invalid output index found');
            }
            if (!(yield this.checkScalar(privateKey))) {
                throw new Error('Invalid private key found');
            }
            return tryRunFunc('deriveSecretKey', derivation, outputIndex, privateKey);
        });
    }
    /**
     * Generates a set of deterministic spend keys for a sub wallet given
     * our root private spend key and the index of the subwallet
     * @param privateKey our root private spend key (seed)
     * @param walletIndex the index of the subwallet
     */
    generateDeterministicSubwalletKeys(privateKey, walletIndex) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!(yield this.checkScalar(privateKey))) {
                throw new Error('Invalid private key found');
            }
            if (!isUInt(walletIndex)) {
                throw new Error('Invalid wallet index found');
            }
            const keys = yield tryRunFunc('generateDeterministicSubwalletKeys', privateKey, walletIndex);
            if (keys) {
                return {
                    privateKey: keys.privateKey || keys.secretKey || keys.SecretKey,
                    publicKey: keys.publicKey || keys.PublicKey
                };
            }
            else {
                throw new Error('Could not generate deterministic subwallet keys');
            }
        });
    }
    /**
     * Generates a key derivation (aB) given the public key and private key
     * @param publicKey
     * @param privateKey
     */
    generateKeyDerivation(publicKey, privateKey) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!(yield this.checkKey(publicKey))) {
                throw new Error('Invalid public key found');
            }
            if (!(yield this.checkScalar(privateKey))) {
                throw new Error('Invalid private key found');
            }
            return tryRunFunc('generateKeyDerivation', publicKey, privateKey);
        });
    }
    /**
     * Generates a key derivation scalar H_s(aB) given the public key and private key
     * @param publicKey the public key
     * @param privateKey the private key
     * @param outputIndex the output index
     */
    generateKeyDerivationScalar(publicKey, privateKey, outputIndex) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!(yield this.checkKey(publicKey))) {
                throw new Error('Invalid public key found');
            }
            if (!(yield this.checkScalar(privateKey))) {
                throw new Error('Invalid private key found');
            }
            if (!isUInt(outputIndex)) {
                throw new Error('Invalid output index found');
            }
            return tryRunFunc('generateKeyDerivationScalar', publicKey, privateKey, outputIndex);
        });
    }
    /**
     * Generates a key image given the public ephemeral and the private ephemeral
     * @param publicEphemeral the public ephemeral of the output
     * @param privateEphemeral the private ephemeral of the output
     */
    generateKeyImage(publicEphemeral, privateEphemeral) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!(yield this.checkKey(publicEphemeral))) {
                throw new Error('Invalid public ephemeral found');
            }
            if (!(yield this.checkScalar(privateEphemeral))) {
                throw new Error('Invalid private ephemeral found');
            }
            return tryRunFunc('generateKeyImage', publicEphemeral, privateEphemeral);
        });
    }
    /**
     * Generates a new random key pair
     */
    generateKeys() {
        return __awaiter(this, void 0, void 0, function* () {
            const keys = yield tryRunFunc('generateKeys');
            if (keys) {
                return {
                    privateKey: keys.privateKey || keys.secretKey || keys.SecretKey,
                    publicKey: keys.publicKey || keys.PublicKey
                };
            }
            else {
                throw new Error('Could not generate keys');
            }
        });
    }
    /**
     * Generates a partial signing key for a multisig ring signature set
     * @param signature the prepared real input signature
     * @param privateKey our private spend key (or multisig private key)
     */
    generatePartialSigningKey(signature, privateKey) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex128(signature)) {
                throw new Error('Invalid signature found');
            }
            if (!(yield this.checkScalar(privateKey))) {
                throw new Error('Invalid private key found');
            }
            return tryRunFunc('generatePartialSigningKey', signature, privateKey);
        });
    }
    /**
     * Generates a private view key from the private spend key
     * @param privateKey the private spend key
     */
    generatePrivateViewKeyFromPrivateSpendKey(privateKey) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!(yield this.checkScalar(privateKey))) {
                throw new Error('Invalid private key found');
            }
            return tryRunFunc('generatePrivateViewKeyFromPrivateSpendKey', privateKey);
        });
    }
    /**
     * Generates ring signatures for the supplied values
     * @param hash the message digest hash (often the transaction prefix hash)
     * @param keyImage the key image of the output being spent
     * @param publicKeys an array of the output keys used for signing (mixins + our output)
     * @param privateEphemeral the private ephemeral of the output being spent
     * @param realIndex the array index of the real output being spent in the publicKeys array
     */
    generateRingSignatures(hash, keyImage, publicKeys, privateEphemeral, realIndex) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex64(hash)) {
                throw new Error('Invalid hash found');
            }
            if (!isHex64(keyImage)) {
                throw new Error('Invalid key image found');
            }
            if (!(yield this.checkScalar(privateEphemeral))) {
                throw new Error('Invalid private key found');
            }
            if (!Array.isArray(publicKeys)) {
                throw new Error('public keys must be an array');
            }
            if (!isUInt(realIndex) || realIndex > publicKeys.length - 1) {
                throw new Error('Invalid real index found');
            }
            publicKeys.forEach((key) => {
                if (!this.checkKey(key)) {
                    throw new Error('Invalid public key found');
                }
            });
            return tryRunFunc('generateRingSignatures', hash, keyImage, publicKeys, privateEphemeral, realIndex);
        });
    }
    /**
     * Generates a signature for the given message digest (hash)
     * @param hash the hash
     * @param publicKey the public key used in signing
     * @param privateKey the private key used to sign
     */
    generateSignature(hash, publicKey, privateKey) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex64(hash)) {
                throw new Error('Invalid hash found');
            }
            if (!(yield this.checkKey(publicKey))) {
                throw new Error('Invalid public key found');
            }
            if (!(yield this.checkScalar(privateKey))) {
                throw new Error('Invalid private key found');
            }
            return tryRunFunc('generateSignature', hash, publicKey, privateKey);
        });
    }
    /**
     * Generates a vew key pair from the private spend key
     * @param privateKey the private spend key
     */
    generateViewKeysFromPrivateSpendKey(privateKey) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!(yield this.checkScalar(privateKey))) {
                throw new Error('Invalid private key found');
            }
            const keys = yield tryRunFunc('generateViewKeysFromPrivateSpendKey', privateKey);
            if (keys) {
                return {
                    privateKey: keys.privateKey || keys.secretKey || keys.SecretKey,
                    publicKey: keys.publicKey || keys.PublicKey
                };
            }
            else {
                throw new Error('Could not generate view keys from private spend key');
            }
        });
    }
    /**
     * Converts a hash to an elliptic curve point
     * @param hash the hash
     */
    hashToEllipticCurve(hash) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex64(hash)) {
                throw new Error('Invalid hash found');
            }
            return tryRunFunc('hashToEllipticCurve', hash);
        });
    }
    /**
     * Converts a hash to a scalar
     * @param hash the hash
     */
    hashToScalar(hash) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex64(hash)) {
                throw new Error('Invalid hash found');
            }
            return tryRunFunc('hashToScalar', hash);
        });
    }
    /**
     * Prepares ring signatures for completion or restoration later
     * @param hash the message digest hash (often the transaction prefix hash)
     * @param keyImage the key image of the output being spent
     * @param publicKeys an array of the output keys used for signing (mixins + our output)
     * @param realIndex the array index of the real output being spent in the publicKeys array
     */
    prepareRingSignatures(hash, keyImage, publicKeys, realIndex) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex64(hash)) {
                throw new Error('Invalid hash found');
            }
            if (!isHex64(keyImage)) {
                throw new Error('Invalid key image found');
            }
            if (!Array.isArray(publicKeys)) {
                throw new Error('publicKeys must be an array');
            }
            if (!isUInt(realIndex) || realIndex > publicKeys.length - 1) {
                throw new Error('Invalid real index found');
            }
            publicKeys.forEach((key) => {
                if (!this.checkKey(key)) {
                    throw new Error('Invalid public key found');
                }
            });
            const result = yield tryRunFunc('prepareRingSignatures', hash, keyImage, publicKeys, realIndex);
            if (result) {
                return {
                    signatures: result.signatures,
                    key: result.key
                };
            }
            else {
                throw new Error('Could not prepare ring signatures');
            }
        });
    }
    /**
     * Re-initializes the underlying cryptographic primitives
     */
    reloadCrypto() {
        return __awaiter(this, void 0, void 0, function* () {
            return initialize();
        });
    }
    /**
     * Restores a key image from a set of partial key images generated by the other
     * participants in a multisig wallet
     * @param publicEphemeral the transaction public ephemeral
     * @param derivation the key derivation of the our output
     * @param outputIndex the index of our output in the transaction
     * @param partialKeyImages the array of partial key images from the needed
     * number of participants in the multisig scheme
     */
    restoreKeyImage(publicEphemeral, derivation, outputIndex, partialKeyImages) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!(yield this.checkKey(publicEphemeral))) {
                throw new Error('Invalid public ephemeral found');
            }
            if (!isHex64(derivation)) {
                throw new Error('Invalid derivation found');
            }
            if (!isUInt(outputIndex)) {
                throw new Error('Invalid output index found');
            }
            if (!Array.isArray(partialKeyImages)) {
                throw new Error('partial key images must be an array');
            }
            partialKeyImages.forEach((key) => {
                if (!isHex64(key)) {
                    throw new Error('Invalid key image found');
                }
            });
            return tryRunFunc('restoreKeyImage', publicEphemeral, derivation, outputIndex, partialKeyImages);
        });
    }
    /**
     * Restores the ring signatures using the previously prepared ring signatures
     * and the necessary number of partial signing keys generated by other
     * participants in the multisig wallet
     * @param derivation the key derivation for the output being spent
     * @param outputIndex the index of the output being spent in the transaction
     * @param partialSigningKeys the array of partial signing keys from the necessary number
     * of participants
     * @param realIndex the index of the real input in the ring signatures
     * @param k the random scalar generated py preparing the ring signatures
     * @param signatures the prepared ring signatures
     */
    restoreRingSignatures(derivation, outputIndex, partialSigningKeys, realIndex, k, signatures) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex64(derivation)) {
                throw new Error('Invalid derivation found');
            }
            if (!isUInt(outputIndex)) {
                throw new Error('Invalid output index found');
            }
            if (!Array.isArray(partialSigningKeys)) {
                throw new Error('partial signing keys must be an array');
            }
            if (!(yield this.checkScalar(k))) {
                throw new Error('Invalid k found');
            }
            if (!Array.isArray(signatures)) {
                throw new Error('signatures must be an array');
            }
            if (!isUInt(realIndex) || realIndex > signatures.length - 1) {
                throw new Error('Invalid real index found');
            }
            partialSigningKeys.forEach((key) => {
                if (!this.checkScalar(key)) {
                    throw new Error('Invalid partial signing key found');
                }
            });
            signatures.forEach((sig) => {
                if (!isHex128(sig)) {
                    throw new Error('Invalid signature found');
                }
            });
            return tryRunFunc('restoreRingSignatures', derivation, outputIndex, partialSigningKeys, realIndex, k, signatures);
        });
    }
    /**
     * Derives the public key using the derivation scalar
     * @param derivationScalar the derivation scalar
     * @param publicKey the public key
     */
    scalarDerivePublicKey(derivationScalar, publicKey) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!(yield this.checkScalar(derivationScalar))) {
                throw new Error('Invalid derivation scalar found');
            }
            if (!(yield this.checkKey(publicKey))) {
                throw new Error('Invalid public key found');
            }
            return tryRunFunc('scalarDerivePublicKey', derivationScalar, publicKey);
        });
    }
    /**
     * Derives the private key using the derivation scalar
     * @param derivationScalar the derivation scalar
     * @param privateKey the private key
     */
    scalarDeriveSecretKey(derivationScalar, privateKey) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!(yield this.checkScalar(derivationScalar))) {
                throw new Error('Invalid derivation scalar found');
            }
            if (!(yield this.checkScalar(privateKey))) {
                throw new Error('Invalid private key found');
            }
            return tryRunFunc('scalarDeriveSecretKey', derivationScalar, privateKey);
        });
    }
    /**
     * Multiplies two key images together
     * @param keyImageA
     * @param keyImageB
     */
    scalarmultKey(keyImageA, keyImageB) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex64(keyImageA)) {
                throw new Error('Invalid key image A found');
            }
            if (!isHex64(keyImageB)) {
                throw new Error('Invalid key image B found');
            }
            return tryRunFunc('scalarmultKey', keyImageA, keyImageB);
        });
    }
    /**
     * Reduces a value to a scalar (mod q)
     * @param data
     */
    scReduce32(data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex64(data)) {
                throw new Error('Invalid data format');
            }
            return tryRunFunc('scReduce32', data);
        });
    }
    /**
     * Calculates the public key of a private key
     * @param privateKey
     */
    secretKeyToPublicKey(privateKey) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!(yield this.checkScalar(privateKey))) {
                throw new Error('Invalid private key found');
            }
            return tryRunFunc('secretKeyToPublicKey', privateKey);
        });
    }
    /**
     * Calculates the merkle tree branch of the given hashes
     * @param hashes the array of hashes
     */
    tree_branch(hashes) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!Array.isArray(hashes)) {
                throw new Error('hashes must be an array');
            }
            hashes.forEach((hash) => {
                if (!isHex64(hash)) {
                    throw new Error('Invalid hash found');
                }
            });
            return tryRunFunc('tree_branch', hashes);
        });
    }
    /**
     * Calculates the depth of the merkle tree
     * @param count the number of hashes in the tree
     */
    tree_depth(count) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isUInt(count)) {
                throw new Error('Invalid count found');
            }
            return tryRunFunc('tree_depth', count);
        });
    }
    /**
     * Calculates the merkle tree hash of the given hashes
     * @param hashes the array of hashes
     */
    tree_hash(hashes) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!Array.isArray(hashes)) {
                throw new Error('hashes must be an array');
            }
            hashes.forEach((hash) => {
                if (!isHex64(hash)) {
                    throw new Error('Invalid hash found');
                }
            });
            return tryRunFunc('tree_hash', hashes);
        });
    }
    /**
     * Calculates the merkle tree hash from the given branch information
     * @param branches the merkle tree branches
     * @param leaf the leaf on the merkle tree
     * @param path the path on the merkle tree
     */
    tree_hash_from_branch(branches, leaf, path) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!Array.isArray(branches)) {
                throw new Error('branches must be an array');
            }
            if (!isHex64(leaf)) {
                throw new Error('Invalid leaf found');
            }
            if (!isUInt(path)) {
                throw new Error('Invalid path found');
            }
            branches.forEach((branch) => {
                if (!isHex64(branch)) {
                    throw new Error('Invalid branch found');
                }
            });
            if (moduleVars.type === Types.NODEADDON) {
                return tryRunFunc('tree_hash_from_branch', branches, leaf, path);
            }
            else {
                return tryRunFunc('tree_hash_from_branch', branches, leaf, path.toString());
            }
        });
    }
    /**
     * Underives a public key instead of deriving it
     * @param derivation the key derivation
     * @param outputIndex the index of the output in the transaction
     * @param outputKey the output key in the transaction
     */
    underivePublicKey(derivation, outputIndex, outputKey) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex64(derivation)) {
                throw new Error('Invalid derivation found');
            }
            if (!isUInt(outputIndex)) {
                throw new Error('Invalid output index found');
            }
            if (!(yield this.checkKey(outputKey))) {
                throw new Error('Invalid output key found');
            }
            return tryRunFunc('underivePublicKey', derivation, outputIndex, outputKey);
        });
    }
    /**
     * Calculates the hash of the data supplied using the cn_slow_hash_v0 method
     * @param data
     */
    cn_slow_hash_v0(data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Invalid data found');
            }
            return tryRunFunc('cn_slow_hash_v0', data);
        });
    }
    /**
     * Calculates the hash of the data supplied using the cn_slow_hash_v1 method
     * @param data
     */
    cn_slow_hash_v1(data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Invalid data found');
            }
            return tryRunFunc('cn_slow_hash_v1', data);
        });
    }
    /**
     * Calculates the hash of the data supplied using the cn_slow_hash_v2 method
     * @param data
     */
    cn_slow_hash_v2(data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Invalid data found');
            }
            return tryRunFunc('cn_slow_hash_v2', data);
        });
    }
    /**
     * Calculates the hash of the data supplied using the cn_lite_slow_hash_v0 method
     * @param data
     */
    cn_lite_slow_hash_v0(data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Invalid data found');
            }
            return tryRunFunc('cn_lite_slow_hash_v0', data);
        });
    }
    /**
     * Calculates the hash of the data supplied using the cn_lite_slow_hash_v1 method
     * @param data
     */
    cn_lite_slow_hash_v1(data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Invalid data found');
            }
            return tryRunFunc('cn_lite_slow_hash_v1', data);
        });
    }
    /**
     * Calculates the hash of the data supplied using the cn_lite_slow_hash_v2 method
     * @param data
     */
    cn_lite_slow_hash_v2(data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Invalid data found');
            }
            return tryRunFunc('cn_lite_slow_hash_v2', data);
        });
    }
    /**
     * Calculates the hash of the data supplied using the cn_dark_slow_hash_v0 method
     * @param data
     */
    cn_dark_slow_hash_v0(data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Invalid data found');
            }
            return tryRunFunc('cn_dark_slow_hash_v0', data);
        });
    }
    /**
     * Calculates the hash of the data supplied using the cn_dark_slow_hash_v1 method
     * @param data
     */
    cn_dark_slow_hash_v1(data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Invalid data found');
            }
            return tryRunFunc('cn_dark_slow_hash_v1', data);
        });
    }
    /**
     * Calculates the hash of the data supplied using the cn_dark_slow_hash_v2 method
     * @param data
     */
    cn_dark_slow_hash_v2(data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Invalid data found');
            }
            return tryRunFunc('cn_dark_slow_hash_v2', data);
        });
    }
    /**
     * Calculates the hash of the data supplied using the cn_dark_lite_slow_hash_v0 method
     * @param data
     */
    cn_dark_lite_slow_hash_v0(data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Invalid data found');
            }
            return tryRunFunc('cn_dark_lite_slow_hash_v0', data);
        });
    }
    /**
     * Calculates the hash of the data supplied using the cn_dark_lite_slow_hash_v1 method
     * @param data
     */
    cn_dark_lite_slow_hash_v1(data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Invalid data found');
            }
            return tryRunFunc('cn_dark_lite_slow_hash_v1', data);
        });
    }
    /**
     * Calculates the hash of the data supplied using the cn_dark_lite_slow_hash_v2 method
     * @param data
     */
    cn_dark_lite_slow_hash_v2(data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Invalid data found');
            }
            return tryRunFunc('cn_dark_lite_slow_hash_v2', data);
        });
    }
    /**
     * Calculates the hash of the data supplied using the cn_turtle_slow_hash_v0 method
     * @param data
     */
    cn_turtle_slow_hash_v0(data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Invalid data found');
            }
            return tryRunFunc('cn_turtle_slow_hash_v0', data);
        });
    }
    /**
     * Calculates the hash of the data supplied using the cn_turtle_slow_hash_v1 method
     * @param data
     */
    cn_turtle_slow_hash_v1(data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Invalid data found');
            }
            return tryRunFunc('cn_turtle_slow_hash_v1', data);
        });
    }
    /**
     * Calculates the hash of the data supplied using the cn_turtle_slow_hash_v2 method
     * @param data
     */
    cn_turtle_slow_hash_v2(data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Invalid data found');
            }
            return tryRunFunc('cn_turtle_slow_hash_v2', data);
        });
    }
    /**
     * Calculates the hash of the data supplied using the cn_turtle_lite_slow_hash_v0 method
     * @param data
     */
    cn_turtle_lite_slow_hash_v0(data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Invalid data found');
            }
            return tryRunFunc('cn_turtle_lite_slow_hash_v0', data);
        });
    }
    /**
     * Calculates the hash of the data supplied using the cn_turtle_lite_slow_hash_v1 method
     * @param data
     */
    cn_turtle_lite_slow_hash_v1(data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Invalid data found');
            }
            return tryRunFunc('cn_turtle_lite_slow_hash_v1', data);
        });
    }
    /**
     * Calculates the hash of the data supplied using the cn_turtle_lite_slow_hash_v2 method
     * @param data
     */
    cn_turtle_lite_slow_hash_v2(data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Invalid data found');
            }
            return tryRunFunc('cn_turtle_lite_slow_hash_v2', data);
        });
    }
    /**
     * Calculates the hash of the data supplied using the cn_soft_shell_slow_hash_v0 method
     * @param data
     * @param height the height of the blockchain
     */
    cn_soft_shell_slow_hash_v0(data, height) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Invalid data found');
            }
            if (!isUInt(height)) {
                throw new Error('Invalid height found');
            }
            return tryRunFunc('cn_soft_shell_slow_hash_v0', data, height);
        });
    }
    /**
     * Calculates the hash of the data supplied using the cn_soft_shell_slow_hash_v1 method
     * @param data
     * @param height the height of the blockchain
     */
    cn_soft_shell_slow_hash_v1(data, height) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Invalid data found');
            }
            if (!isUInt(height)) {
                throw new Error('Invalid height found');
            }
            return tryRunFunc('cn_soft_shell_slow_hash_v1', data, height);
        });
    }
    /**
     * Calculates the hash of the data supplied using the cn_soft_shell_slow_hash_v2 method
     * @param data
     * @param height the height of the blockchain
     */
    cn_soft_shell_slow_hash_v2(data, height) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Invalid data found');
            }
            if (!isUInt(height)) {
                throw new Error('Invalid height found');
            }
            return tryRunFunc('cn_soft_shell_slow_hash_v2', data, height);
        });
    }
    /**
     * Calculates the hash of the data supplied using the chukwa_slow_hash method
     * @param data
     * @param version
     */
    chukwa_slow_hash(data, version = 1) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Invalid data found');
            }
            let func = 'chukwa_slow_hash_';
            switch (version) {
                case 1:
                    func += 'v1';
                    break;
                case 2:
                    func += 'v2';
                    break;
                default:
                    throw new Error('Unknown Chukwa version number');
            }
            return tryRunFunc(func, data);
        });
    }
    /**
     * Calculates the hash of the data supplied using the chukwa_slow_hash_base method
     * @param data
     * @param iterations
     * @param memory
     * @param threads
     */
    chukwa_slow_hash_base(data, iterations, memory, threads) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Invalid data found');
            }
            return tryRunFunc('chukwa_slow_hash_base', data, iterations, memory, threads);
        });
    }
    /**
     * Calculates the hash of the data supplied using the chukwa_slow_hash_v1 method
     * @param data
     */
    chukwa_slow_hash_v1(data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Invalid data found');
            }
            return tryRunFunc('chukwa_slow_hash_v1', data);
        });
    }
    /**
     * Calculates the hash of the data supplied using the chukwa_slow_hash_v2 method
     * @param data
     */
    chukwa_slow_hash_v2(data) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!isHex(data)) {
                throw new Error('Invalid data found');
            }
            return tryRunFunc('chukwa_slow_hash_v2', data);
        });
    }
}
exports.Crypto = Crypto;
/**
 * @ignore
 */
function initialize() {
    if (moduleVars.crypto === null) {
        if (loadNativeAddon()) {
            return true;
        }
        if (loadBrowserWASM()) {
            return true;
        }
        if (loadWASMJS()) {
            return true;
        }
        return loadNativeJS();
    }
    else {
        return true;
    }
}
/**
 * @ignore
 */
function tryRunFunc(...args) {
    return __awaiter(this, void 0, void 0, function* () {
        function tryVectorStringToArray(vs) {
            if (vs instanceof moduleVars.crypto.VectorString) {
                const tmp = [];
                for (let i = 0; i < vs.size(); i++) {
                    tmp.push(vs.get(i));
                }
                return tmp;
            }
            else {
                return vs;
            }
        }
        const func = args.shift();
        return new Promise((resolve, reject) => {
            if (userCryptoFunctions[func]) {
                return resolve(userCryptoFunctions[func](...args));
            }
            else if (moduleVars.type === Types.NODEADDON && moduleVars.crypto[func]) {
                /* If the function name starts with 'check' then it
                   will return a boolean which we can just send back
                   up the stack */
                if (func.indexOf('check') === 0) {
                    return resolve(moduleVars.crypto[func](...args));
                }
                else {
                    const [err, res] = moduleVars.crypto[func](...args);
                    if (err) {
                        return reject(err);
                    }
                    return resolve(res);
                }
            }
            else if (moduleVars.crypto[func]) {
                for (let i = 0; i < args.length; i++) {
                    if (Array.isArray(args[i])) {
                        args[i] = args[i].toVectorString();
                    }
                }
                const res = moduleVars.crypto[func](...args);
                if (typeof res !== 'object' || res instanceof moduleVars.crypto.VectorString) {
                    return resolve(tryVectorStringToArray(res));
                }
                else {
                    Object.keys(res).forEach((key) => {
                        res[key] = tryVectorStringToArray(res[key]);
                    });
                    return resolve(res);
                }
            }
            else {
                return reject(new Error('Could not locate method in underlying Cryptographic library'));
            }
        });
    });
}
/**
 * @ignore
 */
function loadBrowserWASM() {
    if (typeof window === 'undefined') {
        return false;
    }
    try {
        // eslint-disable-next-line @typescript-eslint/ban-ts-comment
        // @ts-ignore
        const Self = window.TurtleCoinCrypto();
        if (Object.getOwnPropertyNames(Self).length === 0 ||
            typeof Self.cn_fast_hash === 'undefined') {
            return false;
        }
        moduleVars.crypto = Self;
        moduleVars.type = Types.WASM;
        return true;
    }
    catch (e) {
        return false;
    }
}
/**
 * @ignore
 */
function loadNativeAddon() {
    try {
        const Self = require('bindings')('turtlecoin-crypto.node');
        if (Object.getOwnPropertyNames(Self).length === 0 ||
            typeof Self.cn_fast_hash === 'undefined') {
            return false;
        }
        moduleVars.crypto = Self;
        moduleVars.type = Types.NODEADDON;
        return true;
    }
    catch (e) {
        return false;
    }
}
/**
 * @ignore
 */
function loadNativeJS() {
    try {
        const Self = require('./turtlecoin-crypto.js')();
        if (Object.getOwnPropertyNames(Self).length === 0 ||
            typeof Self.cn_fast_hash === 'undefined') {
            return false;
        }
        moduleVars.crypto = Self;
        moduleVars.type = Types.JS;
        return true;
    }
    catch (e) {
        return false;
    }
}
/**
 * @ignore
 */
function loadWASMJS() {
    if (typeof window === 'undefined') {
        return false;
    }
    try {
        const Self = require('./turtlecoin-crypto-wasm.js')();
        if (Object.getOwnPropertyNames(Self).length === 0) {
            return false;
        }
        moduleVars.crypto = Self;
        moduleVars.type = Types.WASMJS;
        return true;
    }
    catch (e) {
        return false;
    }
}
/**
 * @ignore
 */
function isHex(value) {
    if (value.length % 2 !== 0) {
        return false;
    }
    const regex = new RegExp('^[0-9a-fA-F]{' + value.length + '}$');
    return regex.test(value);
}
/**
 * @ignore
 */
function isHex64(value) {
    return (isHex(value) && value.length === 64);
}
/**
 * @ignore
 */
function isHex128(value) {
    return (isHex(value) && value.length === 128);
}
/**
 * @ignore
 */
function isUInt(value) {
    return (value === toInt(value) && toInt(value) >= 0);
}
/**
 * @ignore
 */
function toInt(value) {
    if (typeof value === 'number') {
        return value;
    }
    else {
        const tmp = parseInt(value, 10);
        if (tmp.toString().length === value.toString().length) {
            return tmp;
        }
    }
    return false;
}
