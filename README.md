# rlwe

rlwe is a fast, lightweight, and easy-to-use library for doing cryptography involving the ring learning with errors (RLWE) problem.

Note that the library makes no pretensions about being safe from side-channel attacks and should **not** be used in a production environment.
Rather, it is intended to be used in an academic setting.

Specifically, the library implements ...
  * The [Fan-Vercauterean](https://eprint.iacr.org/2012/144.pdf) fully homomorphic cryptosystem
  * [Peikert-style](https://eprint.iacr.org/2014/070.pdf) key exchange & reconciliation*
  * The [Ring-TESLA](https://eprint.iacr.org/2016/030.pdf) digital signature algorithm*
  * The [Knuth-Yao](https://eprint.iacr.org/2017/988.pdf) algorithm for fast discrete noise sampling over a Gaussian distribution
<br><sub><sup>* Implementation not finished yet</sup></sub>

For anyone without significant background on RLWE, I would recommend checking out these links:
* [Homomorphic Encryption from RLWE](https://cryptosith.org/michael/data/talks/2012-01-10-MSR-Cambridge.pdf) 
* [Microsoft's SEAL Library Manual](https://www.microsoft.com/en-us/research/wp-content/uploads/2017/12/sealmanual.pdf) 
* [N1 Analytic's Blog on Homomorphic Encryption using RLWE](https://blog.n1analytics.com/homomorphic-encryption-illustrated-primer/)

However, it is possible to still use this library without in-depth knowledge of how the RLWE cryptographic system works.
This is because most of the algorithmic details have been abstracted away.

Here's an example of what you can do with this library:

```c++
namespace fv = rlwe::fv;

// Set up some parameters for the FV cryptosystem
fv::KeyParameters params(1024, 12289, 2);

// Randomly generate the private key using the given parameters 
fv::PrivateKey priv = fv::GeneratePrivateKey(params);

// Using the private key, generate a corresponding public key
fv::PublicKey pub = fv::GeneratePublicKey(priv);

// Encode some plaintext integer as a polynomial in the plaintext ring
// The coefficients of the polynomial are equal to the binary representation of the integer
fv::Plaintext encoded_plaintext = fv::EncodeInteger(1337, params); 

// Encrypt the plaintext using the public key 
fv::Ciphertext ciphertext = pub.Encrypt(encoded_plaintext);

[...]

// Decrypt the plaintext using the private key
fv::Plaintext decrypted_plaintext = priv.Decrypt(ciphertext);

// Prints "1337"
std::cout << fv::DecodeInteger(decrypted_plaintext, params) << std::endl;
```

## Installation

It's recommended you do an out-of-source build & install.

After cloning into this repository, run:

```
mkdir build && cd build
cmake ..
make
make install
```

## Implementation Details

Internally, rlwe uses [NTL](http://www.shoup.net/ntl/) for doing fast polynomial arithmetic. 
All keys, plaintexts, and ciphertexts store their polynomials as `NTL:ZZX` objects.
However, these polynomials are in the ring `Z_q/(f)` where `f` is a cyclotomic polynomial of the form `x^n + 1`.
Whenever operations are performed on them, they are usually converted to `NTL::ZZ_pX` and a temporary modulus is pushed until the operation completes.

The SHA-256 implementation used was obtained from [zedwood](http://www.zedwood.com/article/cpp-sha256-function).
