// Copyright (c) 2020, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.
'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
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
})(Types || (Types = {}));
/**
 * @ignore
 */
const moduleVars = {
    crypto: null,
    type: Types.UNKNOWN,
};
/**
 * KeyPair object for holding privateKey and publicKey pairs
 */
class KeyPair {
    /**
     * Creates a new KeyPair object
     * @param privateKey the private key
     * @param publicKey the public key
     */
    constructor(privateKey, publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }
}
exports.KeyPair = KeyPair;
/**
 * A PreparedRingSignatures object for holding prepared signatures and the random scalar (k)
 */
class PreparedRingSignatures {
    /**
     * Creates a new PreparedRingSignatures object
     * @param signatures the array of signatures
     * @param key the random scalar key for the signatures
     */
    constructor(signatures, key) {
        this.signatures = signatures;
        this.key = key;
    }
}
exports.PreparedRingSignatures = PreparedRingSignatures;
/**
 * @ignore
 */
// @ts-ignore
Array.prototype.toVectorString = function () {
    if (!moduleVars.crypto.VectorString) {
        throw new Error('VectorString unavailable');
    }
    const arr = new moduleVars.crypto.VectorString();
    this.forEach((key) => arr.push_back(key));
    return arr;
};
class Crypto {
    constructor(config) {
        if (!initialize()) {
            throw new Error('Could not initialize underlying cryptographic library');
        }
        if (config && typeof config === 'object') {
            Object.keys(config).forEach((key) => {
                if (typeof config[key] === 'function') {
                    userCryptoFunctions[key] = config[key];
                }
            });
        }
    }
    get type() {
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
    get isNative() {
        switch (moduleVars.type) {
            case Types.NODEADDON:
                return false;
            default:
                return true;
        }
    }
    get isReady() {
        return (moduleVars.crypto !== null && typeof moduleVars.crypto.cn_fast_hash === 'function');
    }
    set userCryptoFunctions(config) {
        if (config && typeof config === 'object') {
            Object.keys(config).forEach((key) => {
                if (typeof config[key] === 'function') {
                    userCryptoFunctions[key] = config[key];
                }
            });
        }
    }
    calculateMultisigPrivateKeys(privateSpendKey, publicKeys) {
        if (!this.checkScalar(privateSpendKey)) {
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
    }
    calculateSharedPrivateKey(privateKeys) {
        if (!Array.isArray(privateKeys)) {
            throw new Error('privateKeys must be an array');
        }
        privateKeys.forEach((key) => {
            if (!this.checkScalar(key)) {
                throw new Error('Invalid private key found');
            }
        });
        return tryRunFunc('calculateSharedPrivateKey', privateKeys);
    }
    calculateSharedPublicKey(publicKeys) {
        if (!Array.isArray(publicKeys)) {
            throw new Error('publicKeys must be an array');
        }
        publicKeys.forEach((key) => {
            if (!this.checkKey(key)) {
                throw new Error('Invalid public key found');
            }
        });
        return tryRunFunc('calculateSharedPublicKey', publicKeys);
    }
    checkKey(key) {
        if (!isHex64(key)) {
            return false;
        }
        return tryRunFunc('checkKey', key);
    }
    checkRingSignature(hash, keyImage, inputKeys, signatures) {
        return this.checkRingSignatures(hash, keyImage, inputKeys, signatures);
    }
    checkRingSignatures(hash, keyImage, inputKeys, signatures) {
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
    }
    checkScalar(secretKey) {
        if (!isHex64(secretKey)) {
            return false;
        }
        return (secretKey === this.scReduce32(secretKey));
    }
    checkSignature(hash, publicKey, signature) {
        if (!isHex64(hash)) {
            return false;
        }
        if (!this.checkKey(publicKey)) {
            return false;
        }
        if (!isHex128(signature)) {
            return false;
        }
        return tryRunFunc('checkSignature', hash, publicKey, signature);
    }
    cn_fast_hash(data) {
        if (!isHex(data)) {
            throw new Error('Supplied data must be in hexadecimal form');
        }
        const hash = tryRunFunc('cn_fast_hash', data);
        if (hash) {
            return hash;
        }
        try {
            return js_sha3_1.keccak256(Buffer.from(data, 'hex'));
        }
        catch (e) {
            throw e;
        }
    }
    completeRingSignatures(privateKey, realIndex, k, signatures) {
        if (!this.checkScalar(privateKey)) {
            throw new Error('Invalid private key found');
        }
        if (!Array.isArray(signatures)) {
            throw new Error('signatures must be an array');
        }
        if (!isUInt(realIndex) || realIndex > signatures.length - 1) {
            throw new Error('Invalid realIndex format');
        }
        if (!this.checkScalar(k)) {
            throw new Error('Invalid k found');
        }
        signatures.forEach((sig) => {
            if (!isHex128(sig)) {
                throw new Error('Invalid signature found');
            }
        });
        return tryRunFunc('completeRingSignatures', privateKey, realIndex, k, signatures);
    }
    derivationToScalar(derivation, outputIndex) {
        if (!isHex64(derivation)) {
            throw new Error('Invalid derivation found');
        }
        if (!isUInt(outputIndex)) {
            throw new Error('Invalid output index found');
        }
        return tryRunFunc('derivationToScalar', derivation, outputIndex);
    }
    derivePublicKey(derivation, outputIndex, publicKey) {
        if (!isHex64(derivation)) {
            throw new Error('Invalid derivation found');
        }
        if (!isUInt(outputIndex)) {
            throw new Error('Invalid output index found');
        }
        if (!this.checkKey(publicKey)) {
            throw new Error('Invalid public key found');
        }
        return tryRunFunc('derivePublicKey', derivation, outputIndex, publicKey);
    }
    deriveSecretKey(derivation, outputIndex, privateKey) {
        if (!isHex64(derivation)) {
            throw new Error('Invalid derivation found');
        }
        if (!isUInt(outputIndex)) {
            throw new Error('Invalid output index found');
        }
        if (!this.checkScalar(privateKey)) {
            throw new Error('Invalid private key found');
        }
        return tryRunFunc('deriveSecretKey', derivation, outputIndex, privateKey);
    }
    forceJSCrypto() {
        return loadNativeJS();
    }
    generateDeterministicSubwalletKeys(privateKey, walletIndex) {
        if (!this.checkScalar(privateKey)) {
            throw new Error('Invalid private key found');
        }
        if (!isUInt(walletIndex)) {
            throw new Error('Invalid wallet index found');
        }
        const keys = tryRunFunc('generateDeterministicSubwalletKeys', privateKey, walletIndex);
        if (keys) {
            return new KeyPair(keys.privateKey || keys.secretKey || keys.SecretKey, keys.publicKey || keys.PublicKey);
        }
        else {
            throw new Error('Could not generate deterministic subwallet keys');
        }
    }
    generateKeyDerivation(publicKey, privateKey) {
        if (!this.checkKey(publicKey)) {
            throw new Error('Invalid public key found');
        }
        if (!this.checkScalar(privateKey)) {
            throw new Error('Invalid private key found');
        }
        return tryRunFunc('generateKeyDerivation', publicKey, privateKey);
    }
    generateKeyDerivationScalar(publicKey, privateKey, outputIndex) {
        if (!this.checkKey(publicKey)) {
            throw new Error('Invalid public key found');
        }
        if (!this.checkScalar(privateKey)) {
            throw new Error('Invalid private key found');
        }
        if (!isUInt(outputIndex)) {
            throw new Error('Invalid output index found');
        }
        return tryRunFunc('generateKeyDerivationScalar', publicKey, privateKey, outputIndex);
    }
    generateKeyImage(publicKey, privateKey) {
        if (!this.checkKey(publicKey)) {
            throw new Error('Invalid public key found');
        }
        if (!this.checkScalar(privateKey)) {
            throw new Error('Invalid private key found');
        }
        return tryRunFunc('generateKeyImage', publicKey, privateKey);
    }
    generateKeys() {
        const keys = tryRunFunc('generateKeys');
        if (keys) {
            return new KeyPair(keys.privateKey || keys.secretKey || keys.SecretKey, keys.publicKey || keys.PublicKey);
        }
        else {
            throw new Error('Could not generate keys');
        }
    }
    generatePartialSigningKey(signature, privateKey) {
        if (!isHex128(signature)) {
            throw new Error('Invalid signature found');
        }
        if (!this.checkScalar(privateKey)) {
            throw new Error('Invalid private key found');
        }
        return tryRunFunc('generatePartialSigningKey', signature, privateKey);
    }
    generatePrivateViewKeyFromPrivateSpendKey(privateKey) {
        if (!this.checkScalar(privateKey)) {
            throw new Error('Invalid private key found');
        }
        return tryRunFunc('generatePrivateViewKeyFromPrivateSpendKey', privateKey);
    }
    generateRingSignatures(hash, keyImage, publicKeys, privateKey, realIndex) {
        if (!isHex64(hash)) {
            throw new Error('Invalid hash found');
        }
        if (!isHex64(keyImage)) {
            throw new Error('Invalid key image found');
        }
        if (!this.checkScalar(privateKey)) {
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
        return tryRunFunc('generateRingSignatures', hash, keyImage, publicKeys, privateKey, realIndex);
    }
    generateSignature(hash, publicKey, privateKey) {
        if (!isHex64(hash)) {
            throw new Error('Invalid hash found');
        }
        if (!this.checkKey(publicKey)) {
            throw new Error('Invalid public key found');
        }
        if (!this.checkScalar(privateKey)) {
            throw new Error('Invalid private key found');
        }
        return tryRunFunc('generateSignature', hash, publicKey, privateKey);
    }
    generateViewKeysFromPrivateSpendKey(privateKey) {
        if (!this.checkScalar(privateKey)) {
            throw new Error('Invalid private key found');
        }
        const keys = tryRunFunc('generateViewKeysFromPrivateSpendKey', privateKey);
        if (keys) {
            return new KeyPair(keys.privateKey || keys.secretKey || keys.SecretKey, keys.publicKey || keys.PublicKey);
        }
        else {
            throw new Error('Could not generate view keys from private spend key');
        }
    }
    hashToEllipticCurve(hash) {
        if (!isHex64(hash)) {
            throw new Error('Invalid hash found');
        }
        return tryRunFunc('hashToEllipticCurve', hash);
    }
    hashToScalar(hash) {
        if (!isHex64(hash)) {
            throw new Error('Invalid hash found');
        }
        return tryRunFunc('hashToScalar', hash);
    }
    prepareRingSignatures(hash, keyImage, publicKeys, realIndex) {
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
        const result = tryRunFunc('prepareRingSignatures', hash, keyImage, publicKeys, realIndex);
        if (result) {
            return new PreparedRingSignatures(result.signatures, result.key);
        }
        else {
            throw new Error('Could not prepare ring signatures');
        }
    }
    reloadCrypto() {
        return initialize();
    }
    restoreKeyImage(publicEphemeral, derivation, outputIndex, partialKeyImages) {
        if (!this.checkKey(publicEphemeral)) {
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
    }
    restoreRingSignatures(derivation, outputIndex, partialSigningKeys, realIndex, k, signatures) {
        if (!isHex64(derivation)) {
            throw new Error('Invalid derivation found');
        }
        if (!isUInt(outputIndex)) {
            throw new Error('Invalid output index found');
        }
        if (!Array.isArray(partialSigningKeys)) {
            throw new Error('partial signing keys must be an array');
        }
        if (!this.checkScalar(k)) {
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
    }
    scalarDerivePublicKey(derivationScalar, publicKey) {
        if (!this.checkScalar(derivationScalar)) {
            throw new Error('Invalid derivation scalar found');
        }
        if (!this.checkKey(publicKey)) {
            throw new Error('Invalid public key found');
        }
        return tryRunFunc('scalarDerivePublicKey', derivationScalar, publicKey);
    }
    scalarDeriveSecretKey(derivationScalar, privateKey) {
        if (!this.checkScalar(derivationScalar)) {
            throw new Error('Invalid derivation scalar found');
        }
        if (!this.checkScalar(privateKey)) {
            throw new Error('Invalid private key found');
        }
        return tryRunFunc('scalarDeriveSecretKey', derivationScalar, privateKey);
    }
    scalarmultKey(keyImageA, keyImageB) {
        if (!isHex64(keyImageA)) {
            throw new Error('Invalid key image A found');
        }
        if (!isHex64(keyImageB)) {
            throw new Error('Invalid key image B found');
        }
        return tryRunFunc('scalarmultKey', keyImageA, keyImageB);
    }
    scReduce32(data) {
        if (!isHex64(data)) {
            throw new Error('Invalid data format');
        }
        return tryRunFunc('scReduce32', data);
    }
    secretKeyToPublicKey(privateKey) {
        if (!this.checkScalar(privateKey)) {
            throw new Error('Invalid private key found');
        }
        return tryRunFunc('secretKeyToPublicKey', privateKey);
    }
    tree_branch(hashes) {
        if (!Array.isArray(hashes)) {
            throw new Error('hashes must be an array');
        }
        hashes.forEach((hash) => {
            if (!isHex64(hash)) {
                throw new Error('Invalid hash found');
            }
        });
        return tryRunFunc('tree_branch', hashes);
    }
    tree_depth(count) {
        if (!isUInt(count)) {
            throw new Error('Invalid count found');
        }
        return tryRunFunc('tree_depth', count);
    }
    tree_hash(hashes) {
        if (!Array.isArray(hashes)) {
            throw new Error('hashes must be an array');
        }
        hashes.forEach((hash) => {
            if (!isHex64(hash)) {
                throw new Error('Invalid hash found');
            }
        });
        return tryRunFunc('tree_hash', hashes);
    }
    tree_hash_from_branch(branches, leaf, path) {
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
    }
    underivePublicKey(derivation, outputIndex, outputKey) {
        if (!isHex64(derivation)) {
            throw new Error('Invalid derivation found');
        }
        if (!isUInt(outputIndex)) {
            throw new Error('Invalid output index found');
        }
        if (!this.checkKey(outputKey)) {
            throw new Error('Invalid output key found');
        }
        return tryRunFunc('underivePublicKey', derivation, outputIndex, outputKey);
    }
    cn_slow_hash_v0(data) {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }
        return tryRunFunc('cn_slow_hash_v0', data);
    }
    cn_slow_hash_v1(data) {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }
        return tryRunFunc('cn_slow_hash_v1', data);
    }
    cn_slow_hash_v2(data) {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }
        return tryRunFunc('cn_slow_hash_v2', data);
    }
    cn_lite_slow_hash_v0(data) {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }
        return tryRunFunc('cn_lite_slow_hash_v0', data);
    }
    cn_lite_slow_hash_v1(data) {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }
        return tryRunFunc('cn_lite_slow_hash_v1', data);
    }
    cn_lite_slow_hash_v2(data) {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }
        return tryRunFunc('cn_lite_slow_hash_v2', data);
    }
    cn_dark_slow_hash_v0(data) {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }
        return tryRunFunc('cn_dark_slow_hash_v0', data);
    }
    cn_dark_slow_hash_v1(data) {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }
        return tryRunFunc('cn_dark_slow_hash_v1', data);
    }
    cn_dark_slow_hash_v2(data) {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }
        return tryRunFunc('cn_dark_slow_hash_v2', data);
    }
    cn_dark_lite_slow_hash_v0(data) {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }
        return tryRunFunc('cn_dark_lite_slow_hash_v0', data);
    }
    cn_dark_lite_slow_hash_v1(data) {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }
        return tryRunFunc('cn_dark_lite_slow_hash_v1', data);
    }
    cn_dark_lite_slow_hash_v2(data) {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }
        return tryRunFunc('cn_dark_lite_slow_hash_v2', data);
    }
    cn_turtle_slow_hash_v0(data) {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }
        return tryRunFunc('cn_turtle_slow_hash_v0', data);
    }
    cn_turtle_slow_hash_v1(data) {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }
        return tryRunFunc('cn_turtle_slow_hash_v1', data);
    }
    cn_turtle_slow_hash_v2(data) {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }
        return tryRunFunc('cn_turtle_slow_hash_v2', data);
    }
    cn_turtle_lite_slow_hash_v0(data) {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }
        return tryRunFunc('cn_turtle_lite_slow_hash_v0', data);
    }
    cn_turtle_lite_slow_hash_v1(data) {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }
        return tryRunFunc('cn_turtle_lite_slow_hash_v1', data);
    }
    cn_turtle_lite_slow_hash_v2(data) {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }
        return tryRunFunc('cn_turtle_lite_slow_hash_v2', data);
    }
    cn_soft_shell_slow_hash_v0(data, height) {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }
        if (!isUInt(height)) {
            throw new Error('Invalid height found');
        }
        return tryRunFunc('cn_soft_shell_slow_hash_v0', data, height);
    }
    cn_soft_shell_slow_hash_v1(data, height) {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }
        if (!isUInt(height)) {
            throw new Error('Invalid height found');
        }
        return tryRunFunc('cn_soft_shell_slow_hash_v1', data, height);
    }
    cn_soft_shell_slow_hash_v2(data, height) {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }
        if (!isUInt(height)) {
            throw new Error('Invalid height found');
        }
        return tryRunFunc('cn_soft_shell_slow_hash_v2', data, height);
    }
    chukwa_slow_hash(data) {
        if (!isHex(data)) {
            throw new Error('Invalid data found');
        }
        return tryRunFunc('chukwa_slow_hash', data);
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
        if (loadNativeJS()) {
            return true;
        }
        return false;
    }
    else {
        return true;
    }
}
/**
 * @ignore
 */
function tryRunFunc(...args) {
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
    try {
        if (userCryptoFunctions[func]) {
            return userCryptoFunctions[func](...args);
        }
        else if (moduleVars.type === Types.NODEADDON && moduleVars.crypto[func]) {
            /* If the function name starts with 'check' then it
               will return a boolean which we can just send back
               up the stack */
            if (func.indexOf('check') === 0) {
                return moduleVars.crypto[func](...args);
            }
            else {
                const [err, res] = moduleVars.crypto[func](...args);
                if (err) {
                    throw err;
                }
                return res;
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
                return tryVectorStringToArray(res);
            }
            else {
                Object.keys(res).forEach((key) => {
                    res[key] = tryVectorStringToArray(res[key]);
                });
                return res;
            }
        }
        else {
            throw new Error('Could not location method in underlying Cryptographic library');
        }
    }
    catch (e) {
        throw e;
    }
}
/**
 * @ignore
 */
function loadBrowserWASM() {
    if (typeof window === 'undefined') {
        return false;
    }
    try {
        // @ts-ignore
        const Self = window.TurtleCoinCrypto();
        if (Object.getOwnPropertyNames(Self).length === 0) {
            throw new Error('Could not load');
        }
        if (typeof Self.cn_fast_hash === 'undefined') {
            throw new Error('Could not find required method');
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
        if (Object.getOwnPropertyNames(Self).length === 0) {
            throw new Error('Could not load');
        }
        if (typeof Self.cn_fast_hash === 'undefined') {
            throw new Error('Could not find required method');
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
        if (Object.getOwnPropertyNames(Self).length === 0) {
            throw new Error('Could not load');
        }
        if (typeof Self.cn_fast_hash === 'undefined') {
            throw new Error('Could not find required method');
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
            throw new Error('Could not load');
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
    if (typeof value !== 'string') {
        return false;
    }
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
    if (typeof value !== 'string') {
        return false;
    }
    return (isHex(value) && value.length === 64);
}
/**
 * @ignore
 */
function isHex128(value) {
    if (typeof value !== 'string') {
        return false;
    }
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
    else if (typeof value === 'string') {
        const tmp = parseInt(value, 10);
        if (tmp.toString().length === value.toString().length) {
            return tmp;
        }
    }
    return false;
}
