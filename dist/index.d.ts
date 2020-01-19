/**
 * KeyPair object for holding privateKey and publicKey pairs
 */
export declare class KeyPair {
    privateKey: string;
    publicKey: string;
    /**
     * Creates a new KeyPair object
     * @param privateKey the private key
     * @param publicKey the public key
     */
    constructor(privateKey: string, publicKey: string);
}
/**
 * A PreparedRingSignatures object for holding prepared signatures and the random scalar (k)
 */
export declare class PreparedRingSignatures {
    signatures: string[];
    key: string;
    /**
     * Creates a new PreparedRingSignatures object
     * @param signatures the array of signatures
     * @param key the random scalar key for the signatures
     */
    constructor(signatures: string[], key: string);
}
export declare class Crypto {
    constructor(config?: any);
    get type(): string;
    get isNative(): boolean;
    get isReady(): boolean;
    set userCryptoFunctions(config: any);
    calculateMultisigPrivateKeys(privateSpendKey: string, publicKeys: string[]): string[];
    calculateSharedPrivateKey(privateKeys: string[]): string;
    calculateSharedPublicKey(publicKeys: string[]): string;
    checkKey(key: string): boolean;
    checkRingSignature(hash: string, keyImage: string, inputKeys: string[], signatures: string[]): boolean;
    checkRingSignatures(hash: string, keyImage: string, inputKeys: string[], signatures: string[]): boolean;
    checkScalar(secretKey: string): boolean;
    checkSignature(hash: string, publicKey: string, signature: string): boolean;
    cn_fast_hash(data: string): string;
    completeRingSignatures(privateKey: string, realIndex: number, k: string, signatures: string[]): string[];
    derivationToScalar(derivation: string, outputIndex: number): string;
    derivePublicKey(derivation: string, outputIndex: number, publicKey: string): string;
    deriveSecretKey(derivation: string, outputIndex: number, privateKey: string): string;
    forceJSCrypto(): boolean;
    generateDeterministicSubwalletKeys(privateKey: string, walletIndex: number): KeyPair;
    generateKeyDerivation(publicKey: string, privateKey: string): string;
    generateKeyDerivationScalar(publicKey: string, privateKey: string, outputIndex: number): string;
    generateKeyImage(publicKey: string, privateKey: string): string;
    generateKeys(): KeyPair;
    generatePartialSigningKey(signature: string, privateKey: string): string;
    generatePrivateViewKeyFromPrivateSpendKey(privateKey: string): string;
    generateRingSignatures(hash: string, keyImage: string, publicKeys: string[], privateKey: string, realIndex: number): string[];
    generateSignature(hash: string, publicKey: string, privateKey: string): string;
    generateViewKeysFromPrivateSpendKey(privateKey: string): KeyPair;
    hashToEllipticCurve(hash: string): string;
    hashToScalar(hash: string): string;
    prepareRingSignatures(hash: string, keyImage: string, publicKeys: string[], realIndex: number): PreparedRingSignatures;
    reloadCrypto(): boolean;
    restoreKeyImage(publicEphemeral: string, derivation: string, outputIndex: number, partialKeyImages: string[]): string;
    restoreRingSignatures(derivation: string, outputIndex: number, partialSigningKeys: string[], realIndex: number, k: string, signatures: string[]): string[];
    scalarDerivePublicKey(derivationScalar: string, publicKey: string): string;
    scalarDeriveSecretKey(derivationScalar: string, privateKey: string): string;
    scalarmultKey(keyImageA: string, keyImageB: string): string;
    scReduce32(data: string): string;
    secretKeyToPublicKey(privateKey: string): string;
    tree_branch(hashes: string[]): string;
    tree_depth(count: number): number;
    tree_hash(hashes: string[]): string;
    tree_hash_from_branch(branches: string[], leaf: string, path: number): string;
    underivePublicKey(derivation: string, outputIndex: number, outputKey: string): string;
    cn_slow_hash_v0(data: string): string;
    cn_slow_hash_v1(data: string): string;
    cn_slow_hash_v2(data: string): string;
    cn_lite_slow_hash_v0(data: string): string;
    cn_lite_slow_hash_v1(data: string): string;
    cn_lite_slow_hash_v2(data: string): string;
    cn_dark_slow_hash_v0(data: string): string;
    cn_dark_slow_hash_v1(data: string): string;
    cn_dark_slow_hash_v2(data: string): string;
    cn_dark_lite_slow_hash_v0(data: string): string;
    cn_dark_lite_slow_hash_v1(data: string): string;
    cn_dark_lite_slow_hash_v2(data: string): string;
    cn_turtle_slow_hash_v0(data: string): string;
    cn_turtle_slow_hash_v1(data: string): string;
    cn_turtle_slow_hash_v2(data: string): string;
    cn_turtle_lite_slow_hash_v0(data: string): string;
    cn_turtle_lite_slow_hash_v1(data: string): string;
    cn_turtle_lite_slow_hash_v2(data: string): string;
    cn_soft_shell_slow_hash_v0(data: string, height: number): string;
    cn_soft_shell_slow_hash_v1(data: string, height: number): string;
    cn_soft_shell_slow_hash_v2(data: string, height: number): string;
    chukwa_slow_hash(data: string): string;
}
