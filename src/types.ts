export type DID = `did:key:z${string}`
export type Msg = ArrayBuffer|string|Uint8Array

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
 * Ed25519 public key
 * Key type: "ed25519"
 * Magic bytes: [ 0xed, 0x01 ]
 */
export type KeyTypes = Record<string, {
    magicBytes:Uint8Array
    verify:(args:{
        message: Uint8Array
        publicKey: Uint8Array
        signature: Uint8Array
    }) => Promise<boolean>
}>

