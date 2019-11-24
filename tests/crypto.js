// Copyright (c) 2018-2019, The TurtleCoin Developers
//
// Please see the included LICENSE file for more information.

'use strict'

const assert = require('assert')
const describe = require('mocha').describe
const it = require('mocha').it
const TurtleCoinCrypto = require('../')

describe('Core Cryptography', () => {
  it('Generate Random Keys', () => {
    const [err, keys] = TurtleCoinCrypto.generateKeys()

    assert(!err && (keys))
  })

  it('Check Key - Public Key', () => {
    const key = '7849297236cd7c0d6c69a3c8c179c038d3c1c434735741bb3c8995c3c9d6f2ac'
    const isValid = TurtleCoinCrypto.checkKey(key)

    assert(isValid === true)
  })

  it('Check Key - Private Key', () => {
    const key = '4a078e76cd41a3d3b534b83dc6f2ea2de500b653ca82273b7bfad8045d85a400'
    const isValid = TurtleCoinCrypto.checkKey(key)

    assert(isValid === false)
  })

  it('Secret Key to Public Key', () => {
    const key = '4a078e76cd41a3d3b534b83dc6f2ea2de500b653ca82273b7bfad8045d85a400'

    const [err, generatedKey] = TurtleCoinCrypto.secretKeyToPublicKey(key)

    assert(!err && generatedKey === '7849297236cd7c0d6c69a3c8c179c038d3c1c434735741bb3c8995c3c9d6f2ac')
  })

  it('Generate Key Derivation', () => {
    const [err, derivation] = TurtleCoinCrypto.generateKeyDerivation('3b0cc2b066812e6b9fcc42a797dc3c723a7344b604fd4be0b22e06254ff57f94', '6968a0b8f744ec4b8cea5ec124a1b4bd1626a2e6f31e999f8adbab52c4dfa909')

    assert(!err && derivation === '4827dbde0c0994c0979e2f9c046825bb4a065b6e35cabc0290ff5216af060c20')
  })

  it('Derive Public Key', () => {
    const [err, publicKey] = TurtleCoinCrypto.derivePublicKey('4827dbde0c0994c0979e2f9c046825bb4a065b6e35cabc0290ff5216af060c20', 2, '854a637b2863af9e8e8216eb2382f3d16616b3ac3e53d0976fbd6f8da6c56418')

    assert(!err && publicKey === 'bb55bef919d1c9f74b5b52a8a6995a1dc4af4c0bb8824f5dc889012bc748173d')
  })

  it('Underive Public Key: Ours', () => {
    const [err, publicKey] = TurtleCoinCrypto.underivePublicKey('4827dbde0c0994c0979e2f9c046825bb4a065b6e35cabc0290ff5216af060c20', 2, 'bb55bef919d1c9f74b5b52a8a6995a1dc4af4c0bb8824f5dc889012bc748173d')

    assert(!err && publicKey === '854a637b2863af9e8e8216eb2382f3d16616b3ac3e53d0976fbd6f8da6c56418')
  })

  it('Underive Public Key: Not Ours', () => {
    const [err, publicKey] = TurtleCoinCrypto.underivePublicKey('4827dbde0c0994c0979e2f9c046825bb4a065b6e35cabc0290ff5216af060c20', 0, 'bb55bef919d1c9f74b5b52a8a6995a1dc4af4c0bb8824f5dc889012bc748173d')

    assert(!err && publicKey !== '854a637b2863af9e8e8216eb2382f3d16616b3ac3e53d0976fbd6f8da6c56418')
  })

  it('Derive Secret Key', () => {
    const [err, secretKey] = TurtleCoinCrypto.deriveSecretKey('4827dbde0c0994c0979e2f9c046825bb4a065b6e35cabc0290ff5216af060c20', 2, 'd9d555a892a85f64916cae1a168bd3f7f400b6471c7b12b438b599601298210b')

    assert(!err && secretKey === 'e52ece5717f01843e3accc4df651d669e339c31eb8059145e881faae19ad4a0e')
  })

  it('Generate Key Image', () => {
    const [err, keyImage] = TurtleCoinCrypto.generateKeyImage('bb55bef919d1c9f74b5b52a8a6995a1dc4af4c0bb8824f5dc889012bc748173d', 'e52ece5717f01843e3accc4df651d669e339c31eb8059145e881faae19ad4a0e')

    assert(!err && keyImage === '5997cf23543ce2e05c327297a47f26e710af868344859a6f8d65683d8a2498b0')
  })

  it('Generate Deterministic Subwallet #0', () => {
    const [err, spendKey] = TurtleCoinCrypto.generateDeterministicSubwalletKeys('dd0c02d3202634821b4d9d91b63d919725f5c3e97e803f3512e52fb0dc2aab0c', 0)

    assert(!err && spendKey.secretKey === 'dd0c02d3202634821b4d9d91b63d919725f5c3e97e803f3512e52fb0dc2aab0c')
  })

  it('Generate Deterministic Subwallet #1', () => {
    const [err, spendKey] = TurtleCoinCrypto.generateDeterministicSubwalletKeys('dd0c02d3202634821b4d9d91b63d919725f5c3e97e803f3512e52fb0dc2aab0c', 1)

    assert(!err && spendKey.secretKey === 'c55cbe4fd1c49dca5958fa1c7b9212c2dbf3fd5bfec84de741d434056e298600')
  })

  it('Generate Deterministic Subwallet #64', () => {
    const [err, spendKey] = TurtleCoinCrypto.generateDeterministicSubwalletKeys('dd0c02d3202634821b4d9d91b63d919725f5c3e97e803f3512e52fb0dc2aab0c', 64)

    assert(!err && spendKey.secretKey === '29c2afed13271e2bb3321c2483356fd8798f2709af4de3906b6627ec71727108')
  })

  it('Tree Hash', () => {
    const expectedTreeHash = 'dff9b4e047803822e97fb25bb9acb8320648954e15a6ddf6fa757873793c535e'
    const [err, treeHash] = TurtleCoinCrypto.tree_hash([
      'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0',
      '1b606a3f4a07d6489a1bcd07697bd16696b61c8ae982f61a90160f4e52828a7f',
      'c9fae8425d8688dc236bcdbc42fdb42d376c6ec190501aa84b04a4b4cf1ee122',
      '871fcd6823f6a879bb3f33951c8e8e891d4043880b02dfa1bb3be498b50e7578'
    ])
    assert(treeHash === expectedTreeHash && !err)
  })

  it('Tree Branch', () => {
    const expectedTreeBranch = [
      'f49291f9b352701d97dffad838def8cefcc34d1e767e450558261b161ab78cb1',
      '1b606a3f4a07d6489a1bcd07697bd16696b61c8ae982f61a90160f4e52828a7f'
    ]

    const [err, treeBranch] = TurtleCoinCrypto.tree_branch([
      'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0',
      '1b606a3f4a07d6489a1bcd07697bd16696b61c8ae982f61a90160f4e52828a7f',
      'c9fae8425d8688dc236bcdbc42fdb42d376c6ec190501aa84b04a4b4cf1ee122',
      '871fcd6823f6a879bb3f33951c8e8e891d4043880b02dfa1bb3be498b50e7578'
    ])

    assert(!err)
    assert.deepStrictEqual(treeBranch, expectedTreeBranch)
  })
})

describe('Hash Generation Methods', () => {
  const testdata = '0100fb8e8ac805899323371bb790db19218afd8db8e3755d8b90f39b3d5506a9abce4fa912244500000000ee8146d49fa93ee724deb57d12cbc6c6f3b924d946127c7a97418f9348828f0f02'

  const algos = [
    { name: 'CryptoNight Fast Hash', func: 'cn_fast_hash', hash: 'b542df5b6e7f5f05275c98e7345884e2ac726aeeb07e03e44e0389eb86cd05f0' },
    { name: 'CryptoNight v0', func: 'cn_slow_hash_v0', hash: '1b606a3f4a07d6489a1bcd07697bd16696b61c8ae982f61a90160f4e52828a7f' },
    { name: 'CryptoNight v1', func: 'cn_slow_hash_v1', hash: 'c9fae8425d8688dc236bcdbc42fdb42d376c6ec190501aa84b04a4b4cf1ee122' },
    { name: 'CryptoNight v2', func: 'cn_slow_hash_v2', hash: '871fcd6823f6a879bb3f33951c8e8e891d4043880b02dfa1bb3be498b50e7578' },
    { name: 'CryptoNight Lite v0', func: 'cn_lite_slow_hash_v0', hash: '28a22bad3f93d1408fca472eb5ad1cbe75f21d053c8ce5b3af105a57713e21dd' },
    { name: 'CryptoNight Lite v1', func: 'cn_lite_slow_hash_v1', hash: '87c4e570653eb4c2b42b7a0d546559452dfab573b82ec52f152b7ff98e79446f' },
    { name: 'CryptoNight Lite v2', func: 'cn_lite_slow_hash_v2', hash: 'b7e78fab22eb19cb8c9c3afe034fb53390321511bab6ab4915cd538a630c3c62' },
    { name: 'CryptoNight Dark v0', func: 'cn_dark_slow_hash_v0', hash: 'bea42eadd78614f875e55bb972aa5ec54a5edf2dd7068220fda26bf4b1080fb8' },
    { name: 'CryptoNight Dark v1', func: 'cn_dark_slow_hash_v1', hash: 'd18cb32bd5b465e5a7ba4763d60f88b5792f24e513306f1052954294b737e871' },
    { name: 'CryptoNight Dark v2', func: 'cn_dark_slow_hash_v2', hash: 'a18a14d94efea108757a42633a1b4d4dc11838084c3c4347850d39ab5211a91f' },
    { name: 'CryptoNight Dark Lite v0', func: 'cn_dark_lite_slow_hash_v0', hash: 'faa7884d9c08126eb164814aeba6547b5d6064277a09fb6b414f5dbc9d01eb2b' },
    { name: 'CryptoNight Dark Lite v1', func: 'cn_dark_lite_slow_hash_v1', hash: 'c75c010780fffd9d5e99838eb093b37c0dd015101c9d298217866daa2993d277' },
    { name: 'CryptoNight Dark Lite v2', func: 'cn_dark_lite_slow_hash_v2', hash: 'fdceb794c1055977a955f31c576a8be528a0356ee1b0a1f9b7f09e20185cda28' },
    { name: 'CryptoNight Turtle v0', func: 'cn_turtle_slow_hash_v0', hash: '546c3f1badd7c1232c7a3b88cdb013f7f611b7bd3d1d2463540fccbd12997982' },
    { name: 'CryptoNight Turtle v1', func: 'cn_turtle_slow_hash_v1', hash: '29e7831780a0ab930e0fe3b965f30e8a44d9b3f9ad2241d67cfbfea3ed62a64e' },
    { name: 'CryptoNight Turtle v2', func: 'cn_turtle_slow_hash_v2', hash: 'fc67dfccb5fc90d7855ae903361eabd76f1e40a22a72ad3ef2d6ad27b5a60ce5' },
    { name: 'CryptoNight Turtle Lite v0', func: 'cn_turtle_lite_slow_hash_v0', hash: '5e1891a15d5d85c09baf4a3bbe33675cfa3f77229c8ad66c01779e590528d6d3' },
    { name: 'CryptoNight Turtle Lite v1', func: 'cn_turtle_lite_slow_hash_v1', hash: 'ae7f864a7a2f2b07dcef253581e60a014972b9655a152341cb989164761c180a' },
    { name: 'CryptoNight Turtle Lite v2', func: 'cn_turtle_lite_slow_hash_v2', hash: 'b2172ec9466e1aee70ec8572a14c233ee354582bcb93f869d429744de5726a26' },
    { name: 'Chukwa', func: 'chukwa_slow_hash', hash: 'c0dad0eeb9c52e92a1c3aa5b76a3cb90bd7376c28dce191ceeb1096e3a390d2e' }
  ]

  algos.forEach((algo) => {
    it(algo.name, () => {
      const [err, hash] = TurtleCoinCrypto[algo.func](testdata)
      assert(algo.hash === hash && !err)
    })
  })
})
