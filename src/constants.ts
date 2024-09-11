import { CharSize, HashAlg, RsaSize, SymmKeyLength, EccCurve } from './types'

// ECC
export const DEFAULT_ECC_CURVE = EccCurve.P_256
export const ECC_SIGN_ALGORITHM = 'ECDSA'
export const ECC_ENCRYPT_ALGORITHM = 'ECDH'
export const EDWARDS_DID_PREFIX = new Uint8Array([0xed, 0x01])

// RSA
export const RSA_SALT_LENGTH = 128
export const RSA_HASHING_ALGORITHM = HashAlg.SHA_256
export const RSA_ALGORITHM = 'RSA-OAEP'
export const RSA_SIGN_ALGORITHM = 'RSASSA-PKCS1-v1_5'
export const RSA_DID_PREFIX = new Uint8Array([0x00, 0xf5, 0x02])
export const DEFAULT_RSA_SIZE = RsaSize.B2048

// symmetric (AES)
export const AES_GCM = 'AES-GCM' as const
export const DEFAULT_SYMM_ALGORITHM = AES_GCM
export const DEFAULT_SYMM_LEN = SymmKeyLength.B256
export const DEFAULT_CTR_LEN = 64

// misc
export const BASE58_DID_PREFIX = 'did:key:z'
export const DEFAULT_ENCRYPTION_KEY_NAME = 'encryption-key'
export const DEFAULT_SIGNING_KEY_NAME = 'signing-key'
export const BLS_DID_PREFIX = new Uint8Array([0xea, 0x01])
export const DEFAULT_CHAR_SIZE = CharSize.B8
export const DEFAULT_HASH_ALGORITHM = HashAlg.SHA_256
