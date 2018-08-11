#include "rlwe.hpp"

#include <NTL/ZZ_pX.h>
#include <cassert>

using namespace rlwe;

KeyParameters::KeyParameters(long n0, NTL::ZZ q0, NTL::ZZ t0) : n(n0), q(q0), t(t0) {
  // Assert that n is even, assume that it is a power of 2
  assert(n % 2 == 0);

  // Doesn't matter what this is, since the max coefficient is 1 for the cyclotomic polynomial
  ZZ_pPush push(q); 

  // Create a cyclotomic polynomial that serves as the modulus for the ring
  ZZ_pX cyclotomic;

  // The cyclotomic polynomial is x^n + 1 
  SetCoeff(cyclotomic, n, 1);
  SetCoeff(cyclotomic, 0, 1);

  // Build the modulus using the cyclotomic polynomial representation
  build(phi, cyclotomic);
}

PrivateKey KeyParameters::GeneratePrivateKey() const {
  // TODO: Draw error & secret polynomials from discrete Gaussian distribution
  ZZX e;
  ZZX s;

  // Create private key based off of error & secret polynomials 
  PrivateKey priv(e, s, *this);
  return priv;
}

PublicKey KeyParameters::GeneratePublicKey(const PrivateKey & priv) const {
  // Set finite field modulus to be q
  ZZ_pPush push(q); 

  // Compute a, where the coefficients are drawn uniformly from the finite field (integers mod q) 
  ZZ_pX a = NTL::random_ZZ_pX(n);

  // Copy private key parameters into polynomial over finite field
  ZZ_pX s = conv<ZZ_pX>(priv.GetS());
  ZZ_pX e = conv<ZZ_pX>(priv.GetE());

  // Compute b = a * s + e
  ZZ_pX b;
  MulMod(b, a, s, phi);
  b += e;

  // Create public key based off of a & b polynomials
  PublicKey pub(conv<ZZX>(a), conv<ZZX>(b), *this);
  return pub;
}

Ciphertext PublicKey::Encrypt(ZZX plaintext) {
  // Set finite field modulus to be q
  NTL::ZZ_pPush push(params.GetPlainModulus()); 

  Ciphertext ciphertext(plaintext, plaintext);
  return ciphertext;
}

NTL::ZZX PrivateKey::Decrypt(Ciphertext ciphertext) {
  // Set finite field modulus to be q
  NTL::ZZ_pPush push(params.GetPlainModulus()); 

  return ciphertext.GetC1();
}
