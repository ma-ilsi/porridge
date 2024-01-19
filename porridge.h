//
//  porridge.h
//  
//
//  Created by ma on 2024-01-15.
//

#ifndef porridge_h
#define porridge_h

#include <stdint.h>

#endif /* porridge_h */

/// Generates ECDSA nonce in accordance with RFC 6979 using default SHA2 256 as the hash function.
/// Runs without branching or secret-dependent operations (secret-independent / constant time ).
/// - Parameters:
///   - msg: Buffer containing message to be signed using ECDSA.
///   - msg_len: Length of `msg` buffer.
///   - ecdsa_x: 32-length buffer containing client's ECDSA private key
///   - nonce: 256-length outparam buffer to store, in big-endian byte order, the generated nonce.
void ecdsa_nonce(uint8_t *msg, uint32_t msg_len, uint8_t *ecdsa_x, uint8_t *nonce);
