export type DID = `did:key:z${string}`
export type Msg = ArrayBuffer|string|Uint8Array
export type PrivateKey = CryptoKey
export type PublicKey = CryptoKey
export type SymmKey = CryptoKey
export type CipherText = ArrayBuffer

export type SymmAlg = 'AES-CTR'|'AES-CBC'|'AES-GCM'

export enum EccCurve {
    P_256 = 'P-256',
    P_384 = 'P-384',
    P_521 = 'P-521',
}

export enum RsaSize {
    B1024 = 1024,
    B2048 = 2048,
    B4096 = 4096
}

export enum SymmKeyLength {
    B128 = 128,
    B192 = 192,
    B256 = 256,
}

export type SymmKeyOpts = {
    alg:SymmAlg
    length:SymmKeyLength
    iv:ArrayBuffer
}

export enum HashAlg {
    SHA_1 = 'SHA-1',
    SHA_256 = 'SHA-256',
    SHA_384 = 'SHA-384',
    SHA_512 = 'SHA-512',
}

export enum CharSize {
    B8 = 8,
    B16 = 16,
}

export enum KeyUse {
    Encrypt = 'encryption',  // encrypt/decrypt
    Sign = 'signing',  // sign
}

export type KeyAlgorithm = 'bls12-381'|'ed25519'|'rsa'

/**
 * Using the key type as the record property name (ie. string = key type)
 *
 * The magic bytes are the `code` found in https://github.com/multiformats/multicodec/blob/master/table.csv
 * encoded as a variable integer (more info about that at https://github.com/multiformats/unsigned-varint).
 *
 * The key type is also found in that table.
 * It's the name of the codec minus the `-pub` suffix.
 *
 * Example
 * -------
 * _Ed25519 public key_
 * Key type: "ed25519"
 * Magic bytes: [ 0xed, 0x01 ]
 */
export type KeyTypes = Record<KeyAlgorithm, {
    magicBytes:Uint8Array
    verify:(args:{
        message:Uint8Array
        publicKey:Uint8Array
        signature:Uint8Array
    })=>Promise<boolean>
}>
