# librlwe

*librlwe* is a lightweight, easy-to-use library for doing ring-learning with errors (RLWE) cryptography.

For anyone without significant background on RLWE, I would recommend you check out these links:
* [N1 Analytic's Blog on Homomorphic Encryption using RLWE](https://blog.n1analytics.com/homomorphic-encryption-illustrated-primer/)
* [Homomorphic Encryption from RLWE](https://cryptosith.org/michael/data/talks/2012-01-10-MSR-Cambridge.pdf) - presentation given at Cambridge
* [Microsoft's SEAL Library Manual](https://www.microsoft.com/en-us/research/wp-content/uploads/2017/12/sealmanual.pdf) - of which this is based off of
* [Parameters for RLWE Cryptography](http://www.ringlwe.info/parameters-for-rlwe.html)

Here's an example of what you can do with this library:

```
// Set up some parameters for the RLWE algorithm
rlwe::KeyParameters params(1024, NTL::ZZ(9214347247561474048), NTL::ZZ(290764801));

// Generate a keypair
rlwe::PrivateKey priv = params.GeneratePrivateKey();
rlwe::PublicKey pub = params.GeneratePublicKey();

// Encode some plaintext message as a polynomial in the plaintext ring
NTL::ZZX encoded_plaintext = params.Encode("wowee");

// Encrypt the plaintext using the public key 
rlwe::Ciphertext ciphertext = pub.Encrypt(encoded_plaintext);

[...]

// Decrypt the plaintext using the private key
NTL::ZZX decrypted_plaintext = priv.Decrypt(ciphertext);

// Prints "wowee"
std::cout << params.Decode(decrypted_plaintext) << std::endl;
```

All of the RLWE algorithmic details have been abstracted away for user convenience. 
However, accessing the key internals is trivial.

```
// Get the secret from the private key
// This is will be a polynomial in Z[x]/(f) over the finite field GF2
NTL::ZZX secret = priv.GetS();

// Get the two elements that compose the public key
// p1 = a polynomial in Z[x]/(f) over the finite field Fq
// p0 = -(p1 * secret + e) also in the same polynomial ring over the same finite field
// (e = some error chosen from a discrete Gaussian distribution with deviation = 3.192)
NTL::ZZX p0 = priv.GetP0();
NTL::ZZX p1 = priv.GetP1();
```

Internally, librlwe uses [NTL](http://www.shoup.net/ntl/) for doing fast polynomial arthimetic. 
`NTL:ZZX` refers to any polynomial over the set of integers.
However, these polynomials must be limited to certain rings in the keys for RLWE to work.
