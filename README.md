# Porridge
Secret independent (constant time) implementation of an ECDSA deterministic nonce generator ([RFC 6979](https://www.rfc-editor.org/rfc/rfc6979)) written in portable C99.

![three_big_bowls_of_porridge_on_a_desk_windows_summer](https://github.com/ma-ilsi/porridge/assets/107931159/3dbf6ef3-b76f-4d47-8c35-d1c73ef51c8f)

## Overview

Nonces used for the ECDSA signing algorithm have been notoriously misunderstood and/or poorly generated resulting in a plethora of private key compromisations and beautiful research on the topic:

- [Minerva team describing "the curse of ECDSA nonces"](https://minerva.crocs.fi.muni.cz/).
- [Daniel J Bernstein's commentary](https://blog.cr.yp.to/20191024-eddsa.html) on the Minerva attacks & fragility of ECDSA (in comparison to EdDSA).
- Famous video presentation: [PS3 Epic Fail](https://media.ccc.de/v/27c3-4087-en-console_hacking_2010#t=2307) by fail0verflow, demonstrating a Sony private key compromise.
- [Biased Nonce Sense paper](https://eprint.iacr.org/2019/023), compromising hundreds of cryptocurrency private keys.

To avoid such misuse of the signing algorithm, deterministic nonce generation is a necessity. Indeed, reusing a single nonce leads to a private key compromise. RFC 6979 describes a digestible algorithm to generate deterministic nonces for ECDSA, minimizing the success of such nonce-based attacks.

## Features

Currently, porridge is in draft-status. Planned features include:

- `ecdsa_nonce` that clients can invoke to safely generate an ECDSA nonce.
- SHA2-256 hashing algorithm ([FIPS PUB 180-4 Secure Hash Standard](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)) private implementation.
- HMAC with SHA2-256 private ([RFC 2104](https://www.rfc-editor.org/rfc/rfc2104)) private implementation.
- Integration of SHA2-512 sooner or later.
- All code runtime is to be secret-independent (does not branch based on secret data) to avoid sidechannel leaks pertaining to the generated nonce.
- Simple to use, single-header style (or two file) library.

#### What is _secret independent_ runtime?
Referred to as _constant runtime_ in some cryptographic literature, an implementation that is secret-independent always runs in the same amount of time regardless of the secret data it may use. In other words, the code does not branch based on secret data.
This mitigates leaking information about secret data to an attacker that is observing the runtime of the implementation on various inputs.

## Why _porridge_?
The idea of determinstic nonces, from an artistic point  of view, represents the _just right_ notion of Goldilocks, the fictional character of the famous tale: _Goldilocks and the Three Bears_.
The nonce is not blazingly random (too hot), nor a constant value (too cold), but rather deterministicly chosen to avoid the pitfalls of the other temperatures (just right).
Thomas Pornin, the author of RFC 6979, is also the author of BearSSL. 
And so, in a gentle composition of the preceeding, this repository was named *porridge*.

