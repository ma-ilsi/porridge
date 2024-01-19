//
//  porridge.c
//  
//
//  Created by ma-ilsi on 2024-01-15.
//

#include "porridge.h"

static void hash_sha2_256(uint8_t *msg, uint32_t msg_len, uint8_t *dest);
static void hmac_sha2_256(uint8_t *src, uint32_t src_len, uint8_t key, uint32_t key_len, uint8_t *dest);


/// Generates ECDSA nonce in accordance with RFC 6979 using a default hash function, SHA2 256.
/// Runs without branching or secret-dependent operations (secret-independent / constant time ).
/// - Parameters:
///   - msg: `uint8_t` buffer containing message to be signed using ECDSA.
///   - msg_len: Length of `msg` buffer.
///   - ecdsa_x: `uint8_t[32]` buffer containing client's ECDSA private key
///   - nonce: 256-length outparam buffer to store, in big-endian byte order, the generated nonce.
void ecdsa_nonce(uint8_t *msg, uint32_t msg_len, uint8_t *ecdsa_x, uint8_t *nonce) {
    
    //draft-like, in progress. See https://www.rfc-editor.org/rfc/rfc6979
    //TODO: consider also supporting SHA2 512
        
    uint8_t *ptr = msg;
    
    int e, e2, e3;
    
    uint8_t buf256[256];
    uint8_t ecdsa_z1[256];
    uint8_t ecdsa_z2[256];
    uint8_t ecdsa_b_out[256];
    uint8_t ecdsa_V[32];
    uint8_t ecdsa_K[32];
    uint8_t ecdsa_k[32];
    uint8_t ecdsa_rs[32];
    
    uint8_t ecdsa_q[256] = {\
        1,1,1,1,1,1,1,1, \
        1,1,1,1,1,1,1,1, \
        1,1,1,1,1,1,1,1, \
        1,1,1,1,1,1,1,1, \
        0,0,0,0,0,0,0,0, \
        0,0,0,0,0,0,0,0, \
        0,0,0,0,0,0,0,0, \
        0,0,0,0,0,0,0,0, \
        1,1,1,1,1,1,1,1, \
        1,1,1,1,1,1,1,1, \
        1,1,1,1,1,1,1,1, \
        1,1,1,1,1,1,1,1, \
        1,1,1,1,1,1,1,1, \
        1,1,1,1,1,1,1,1, \
        1,1,1,1,1,1,1,1, \
        1,1,1,1,1,1,1,1, \
        1,0,1,1,1,1,0,0, /*bc*/ \
        1,1,1,0,0,1,1,0, /*e6*/ \
        1,1,1,1,1,0,1,0, /*fa*/ \
        1,0,1,0,1,1,0,1, /*ad*/ \
        1,0,1,0,0,1,1,1, /*a7*/ \
        0,0,0,1,0,1,1,1, /*17*/ \
        1,0,0,1,1,1,1,0, /*9e*/ \
        1,0,0,0,0,1,0,0, /*84*/ \
        1,1,1,1,0,0,1,1, /*f3*/ \
        1,0,1,1,1,0,0,1, /*b9*/ \
        1,1,0,0,1,0,1,0, /*cA*/ \
        1,1,0,0,0,0,1,0, /*c2*/ \
        1,1,1,1,1,1,0,0, /*Fc*/ \
        0,1,1,0,0,0,1,1, /*63*/ \
        0,0,1,0,0,1,0,1, /*25*/ \
        0,1,0,1,0,0,0,1, /*51*/ \
    };
    
    //hash the message to be signed using the ecdsa sign function hash
    hash_sha2_256(msg, msg_len, ecdsa_z2);
    
    //expand 32 bytes of the hash in to bits, this is rfc6979 2.3.2
    ptr = ecdsa_z1;
    for (e = 0; e < 32; e++) {

        *(ptr++) = (128 & ecdsa_z2[e]) >> 7;
        *(ptr++) = (64 & ecdsa_z2[e]) >> 6;
        *(ptr++) = (32 & ecdsa_z2[e]) >> 5;
        *(ptr++) = (16 & ecdsa_z2[e]) >> 4;
        *(ptr++) = (8 & ecdsa_z2[e]) >> 3;
        *(ptr++) = (4 & ecdsa_z2[e]) >> 2;
        *(ptr++) = (2 & ecdsa_z2[e]) >> 1;
        *(ptr++) = (1 & ecdsa_z2[e]) >> 0;

    }

    //save z1 in to z2, we'll need z1 in case we did not need to mod q
    for (e = 0; e < 256; e++) { ecdsa_z2[e] = ecdsa_z1[e]; }

    //now we unconditionally reduce z2 by q to simulate mod q case
    for (e = 0; e < 256; e++) {
        
        //negate all bits step 1 of carry bits
        for (e2 = 0; e2 < 256; e2++) { ecdsa_b_out[e2] = ecdsa_z2[e2] ^ 1; }
        
        //step 2 of setting carry bits
        //btw &= is constant right? no lazy stuff right?
        for (e2 = 0; e2 < 256; e2++) { ecdsa_b_out[e2] &= ecdsa_q[e2]; }

        //subtraction logic
        for (e2 = 0; e2 < 256; e2++) { ecdsa_z2[e2] ^= ecdsa_q[e2]; }

        //simulating left shift by 8 bits in the next two lines
        for (e2 = 0; e2 < 255 - e; e2++) { ecdsa_q[e2] = ecdsa_b_out[e2 + 1]; }
        ecdsa_q[255 - e] = 0;

    }

    //now z1 has the original and z2 has the q-reduced version of z1
    //now we need to know if z1 was truly already less than q
    //so we take the result of z1 bit < q bit and multiply it in a loop to write z1 in to z2
    //so as soon as z1 msb is 0 and q msb is 1, we replace all z2 bits with all z1 bits
    //otherwise the loop runs empty since the write is dependent on result, which is 0 if z1 > q
    //in the end we simply use z2 as the final correct result.

    for (e = 0; e < 256; e++) {

        e2 = ecdsa_z1[e] < ecdsa_q[e];

        //the |= lets us retain z2 when e2 = 0
        for (e3 = 0; e3 < 256; e3++) { ecdsa_z2[e] |= ((ecdsa_z1[e]) & e2); }

    }

    //now we pack z2 in to bytes -- shouldn't we pack before the above loop? that would be much faster...

    ptr = ecdsa_z2;

    for (e = 0; e < 32; e++) {

        //we need to &= on the first one in order to clear any previous bits of that byte
        //after that we keep using |= for the rest of the byte in order to save previously set bits
        ecdsa_z1[e] &= *(ptr++) << 7;
        ecdsa_z1[e] |= *(ptr++) << 6;
        ecdsa_z1[e] |= *(ptr++) << 5;
        ecdsa_z1[e] |= *(ptr++) << 4;
        ecdsa_z1[e] |= *(ptr++) << 3;
        ecdsa_z1[e] |= *(ptr++) << 2;
        ecdsa_z1[e] |= *(ptr++) << 1;
        ecdsa_z1[e] |= *(ptr++) << 0;

    }

    //h1 = H(M) as in rfc6979 3.2.a is now stored in z1
    //now we init V and K
    for (e = 0; e < 32; e++) { ecdsa_V[e] = 1; }
    for (e = 0; e < 32; e++) { ecdsa_K[e] = 0; }

    //we must also make sure certificate private key < ecdsa_q, value-wise
    //store/prepare the message to be HMACd
    ptr = ecdsa_z2;
    for (e = 0; e < 32; e++) { *(ptr)++ = ecdsa_V[e]; }
    *(ptr)++ = 0;
    
    for (e = 0; e < 32; e++) { *(ptr)++ = ecdsa_x[e]; }
    for (e = 0; e < 32; e++) { *(ptr)++ = ecdsa_z1[e]; }

    //now apply the hmac
    hmac_sha2_256(ecdsa_z2, 97, ecdsa_K, 32, ptr);
    
    //copy hmac result in to ecdsa_K
    for (e = 0; e < 32; e++) { ecdsa_K[e] = *(ptr)++; }
    
    //now do step e, no need to copy the result , just make the destination be ecdsa_V
    //note the message length is passed as 32
    hmac_sha2_256( ecdsa_z2, 32, ecdsa_K, 32, ecdsa_V);

    //step f is to repeat above with a small difference: note 3rd line down assignment =1 vs above =0
    ptr = ecdsa_z2;
    for (e = 0; e < 32; e++) { *(ptr)++ = ecdsa_V[e]; }
    *(ptr)++ = 1;

    for (e = 0; e < 32; e++) { *(ptr)++ = ecdsa_x[e]; }
    for (e = 0; e < 32; e++) { *(ptr)++ = ecdsa_z1[e]; }

    hmac_sha2_256(ecdsa_z2, 97, ecdsa_K, 32, ptr);
    for (e = 0; e < 32; e++) { ecdsa_K[e] = *(ptr)++; }
    hmac_sha2_256(ecdsa_z2, 32, ecdsa_K, 32, ecdsa_V);


    //now we do step h

    e2 = 0;
    e3 = 0;

    do {
        //TODO: this can change if we allow sha2 512
        //replaced T with k since we never do concatenation (size is 256 bits per HMAC) so we just go straight to storing T in k
        ptr = ecdsa_k;

        hmac_sha2_256(ecdsa_V, 32, ecdsa_K, 32, ptr);
        for (e = 0; e < 32; e++) { ecdsa_V[e] = *(ptr)++; }

        //now ecdsa_k is ecdsa_V as long as it is less than ecdsa_q
        //to compare k to q we use < to trigger a result of 1 as soon as k is detected to be smaller
        //each iteration we | the result with e3 = 0 to keep any previous detection until the loop is done (secret indp. aka constant time)
        //we place step h into a while !(result) loop, where result is the detection of k being smaller than q
        // oh... and we might have to unpack ... lol

        ptr = ecdsa_z1;

        for (e = 0; e < 32; e++) {

            *(ptr++) = (128 & ecdsa_k[e]) >> 7;
            *(ptr++) = (64 & ecdsa_k[e]) >> 6;
            *(ptr++) = (32 & ecdsa_k[e]) >> 5;
            *(ptr++) = (16 & ecdsa_k[e]) >> 4;
            *(ptr++) = (8 & ecdsa_k[e]) >> 3;
            *(ptr++) = (4 & ecdsa_k[e]) >> 2;
            *(ptr++) = (2 & ecdsa_k[e]) >> 1;
            *(ptr++) = (1 & ecdsa_k[e]) >> 0;

        }

        //unpacked k is now in z1

        for (e = 0; e < 256; e++) {
            
            //translation: once we get 1, then 1 always stays...
            e2 |= ecdsa_z1[e] < ecdsa_q[e];

        }

        //make sure its is not all 0 as rfc says
        for (e = 0; e < 256; e++) {
            
            //translation: once we get 1, then 1 always stays...
            e3 |= ecdsa_z1[e] > 0;
            
        }

    } while (!(e2 && e3));


    //nonce is now in ecdsa_k
    
    
    //TODO: write nonce to a dest. buffer? Becasue I'd rather have clients alloc instead of us.
    
}


//TODO: sha256 six functions defined in 4.1.2
#define ch(x,y,z) ;
#define maj(x,y,z) ;

#define bigsigma0(x) ;
#define bigsigma1(x) ;

#define littlesigma0(x) ;
#define littlesigma1(x) ;


static const uint8_t sha256_iv[256] = {\
    0,1,1,0,1,0,1,0, /*6a*/ \
    0,0,0,0,1,0,0,1, /*09*/ \
    1,1,1,0,0,1,1,0, /*e6*/ \
    0,1,1,0,0,1,1,1, /*67*/ \
    1,0,1,1,1,0,1,1, /*bb*/ \
    0,1,1,0,0,1,1,1, /*67*/ \
    1,0,1,0,1,1,1,0, /*ae*/ \
    1,0,0,0,0,1,0,1, /*85*/ \
    0,0,1,1,1,1,0,0, /*3c*/ \
    0,1,1,0,1,1,1,0, /*6e*/ \
    1,1,1,1,0,0,1,1, /*f3*/ \
    0,1,1,1,0,0,1,0, /*72*/ \
    1,0,1,0,0,1,0,1, /*a5*/ \
    0,1,0,0,1,1,1,1, /*4f*/ \
    1,1,1,1,0,1,0,1, /*f5*/ \
    0,0,1,1,1,0,1,0, /*3a*/ \
    0,1,0,1,0,0,0,1, /*51*/ \
    0,0,0,0,1,1,1,0, /*0e*/ \
    0,1,0,1,0,0,1,0, /*52*/ \
    0,1,1,1,1,1,1,1, /*7f*/ \
    1,0,0,1,1,0,1,1, /*9b*/ \
    0,0,0,0,0,1,0,1, /*05*/ \
    0,1,1,0,1,0,0,0, /*68*/ \
    1,0,0,0,1,1,0,0, /*8c*/ \
    0,0,0,1,1,1,1,1, /*1f*/ \
    1,0,0,0,0,0,1,1, /*83*/ \
    1,1,0,1,1,0,0,1, /*d9*/ \
    1,0,1,0,1,0,1,1, /*ab*/ \
    0,1,0,1,1,0,1,1, /*5b*/ \
    1,1,1,0,0,0,0,0, /*e0*/ \
    1,1,0,0,1,1,0,1, /*cd*/ \
    0,0,0,1,1,0,0,1, /*19*/ \
};

static void hash_sha2_256(uint8_t *msg, uint32_t msg_len, uint8_t *dest) {
    
    //TODO: sha256 implementation - draft in progress. See https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
    
    //TODO: add padding to the message. Guaranteed 65 bytes to be added: byte "1" and the "l" number in base2
    
    //Initialize the hash value as in  5.3.3
    uint8_t h0[32] = {
        0,1,1,0,1,0,1,0, /*6a*/ \
        0,0,0,0,1,0,0,1, /*09*/ \
        1,1,1,0,0,1,1,0, /*e6*/ \
        0,1,1,0,0,1,1,1, /*67*/ \
    };
    uint8_t h1[32] = {
        1,0,1,1,1,0,1,1, /*bb*/ \
        0,1,1,0,0,1,1,1, /*67*/ \
        1,0,1,0,1,1,1,0, /*ae*/ \
        1,0,0,0,0,1,0,1, /*85*/ \
    };
    uint8_t h2[32] = {
        0,0,1,1,1,1,0,0, /*3c*/ \
        0,1,1,0,1,1,1,0, /*6e*/ \
        1,1,1,1,0,0,1,1, /*f3*/ \
        0,1,1,1,0,0,1,0, /*72*/ \
    };
    uint8_t h3[32] = {
        1,0,1,0,0,1,0,1, /*a5*/ \
        0,1,0,0,1,1,1,1, /*4f*/ \
        1,1,1,1,0,1,0,1, /*f5*/ \
        0,0,1,1,1,0,1,0, /*3a*/ \
    };
    uint8_t h4[32] = {
        0,1,0,1,0,0,0,1, /*51*/ \
        0,0,0,0,1,1,1,0, /*0e*/ \
        0,1,0,1,0,0,1,0, /*52*/ \
        0,1,1,1,1,1,1,1, /*7f*/ \
    };
    uint8_t h5[32] = {
        1,0,0,1,1,0,1,1, /*9b*/ \
        0,0,0,0,0,1,0,1, /*05*/ \
        0,1,1,0,1,0,0,0, /*68*/ \
        1,0,0,0,1,1,0,0, /*8c*/ \
    };
    uint8_t h6[32] = {
        0,0,0,1,1,1,1,1, /*1f*/ \
        1,0,0,0,0,0,1,1, /*83*/ \
        1,1,0,1,1,0,0,1, /*d9*/ \
        1,0,1,0,1,0,1,1, /*ab*/ \
    };
    uint8_t h7[32] = {
        0,1,0,1,1,0,1,1, /*5b*/ \
        1,1,1,0,0,0,0,0, /*e0*/ \
        1,1,0,0,1,1,0,1, /*cd*/ \
        0,0,0,1,1,0,0,1, /*19*/
    };
    
    return;
}

static void hmac_sha2_256(uint8_t *src, uint32_t src_len, uint8_t key, uint32_t key_len, uint8_t *dest) {
    
    //TODO: hmac with sha256 implementation. See https://www.rfc-editor.org/rfc/rfc2104
    
    return;
}

