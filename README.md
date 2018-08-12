# librlwe

**librlwe** is a fast, lightweight, and easy-to-use library for doing ring-learning with errors (RLWE) cryptography.

For anyone without significant background on RLWE, I would recommend checking out these links:
* [N1 Analytic's Blog on Homomorphic Encryption using RLWE](https://blog.n1analytics.com/homomorphic-encryption-illustrated-primer/)
* [Homomorphic Encryption from RLWE](https://cryptosith.org/michael/data/talks/2012-01-10-MSR-Cambridge.pdf) - presentation given at MSR Cambridge
* [Microsoft's SEAL Library Manual](https://www.microsoft.com/en-us/research/wp-content/uploads/2017/12/sealmanual.pdf) - of which this is based off of
* [Parameters for RLWE Cryptography](http://www.ringlwe.info/parameters-for-rlwe.html)

Here's an example of what you can do with librlwe:

```
// Set up some parameters for the RLWE algorithm
rlwe::KeyParameters params(1024, NTL::ZZ(9214347247561474048), NTL::ZZ(290764801));

// Generate a keypair
rlwe::PrivateKey priv = params.GeneratePrivateKey();
rlwe::PublicKey pub = params.GeneratePublicKey();

// Encode some plaintext integer as a polynomial in the plaintext ring
rlwe::Plaintext encoded_plaintext = params.EncodeInteger(NTL:ZZ(1337));

// Encrypt the plaintext using the public key 
rlwe::Ciphertext ciphertext = pub.Encrypt(encoded_plaintext);

[...]

// Decrypt the plaintext using the private key
rlwe::Plaintext decrypted_plaintext = priv.Decrypt(ciphertext);

// Prints "1337"
std::cout << params.DecodeInteger(decrypted_plaintext) << std::endl;
```

Internally, librlwe uses [NTL](http://www.shoup.net/ntl/) for doing fast polynomial arithmetic. 
`NTL:ZZX` refers to any arbitrary polynomial whose coefficients are over the set of integers.
However, all polynomials generated or used by librlwe are in the ring `Z_q/(f)` where `f` is a cyclotomic polynomial of the form `x^n + 1`.
Whenever operations are performed on them, they are usually converted to `NTL::ZZ_pX` and a temporary modulus is pushed until the operation completes.
