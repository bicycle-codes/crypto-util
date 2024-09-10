import { createDebug } from '@bicycle-codes/debug'
import tweetnacl from 'tweetnacl'
const debug = createDebug()

/**
 * Convert a base64 public key to a DID (did:key).
 */
export function publicKeyToDid(
    crypto:Crypto.Implementation,
    publicKey:Uint8Array,
    keyType:string
): string {
    // Prefix public-write key
    const prefix = crypto.did.keyTypes[ keyType ]?.magicBytes
    if (prefix === null) {
      throw new Error(`Key type '${keyType}' not supported,
        available types: ${Object.keys(crypto.did.keyTypes).join(", ")}`)
    }
  
    const prefixedBuf = uint8arrays.concat([ prefix, publicKey ])
  
    // Encode prefixed
    return BASE58_DID_PREFIX + uint8arrays.toString(prefixedBuf, "base58btc")
}

export async function ed25519Verify ({
    message,
    publicKey,
    signature
}:{
    message: Uint8Array
    publicKey: Uint8Array
    signature: Uint8Array
}):Promise<boolean> {
    return tweetnacl.sign.detached.verify(message, signature, publicKey)
}
