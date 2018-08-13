#include "rlwe.hpp"

#include <cassert>
#include <NTL/ZZ_pX.h>

using namespace rlwe;

KeyParameters::KeyParameters(long n0, ZZ q0, ZZ t0) : n(n0), q(q0), t(t0), q_div_t(q0 / t0) {
  // Assert that n is even, assume that it is a power of 2
  assert(n % 2 == 0);

  // Doesn't matter what this is, since the max coefficient is 1 for the cyclotomic polynomial
  ZZ_pPush push;
  ZZ_p::init(q);

  // Create a cyclotomic polynomial that serves as the modulus for the ring
  ZZ_pX cyclotomic;

  // The cyclotomic polynomial is x^n + 1 
  SetCoeff(cyclotomic, n, 1);
  SetCoeff(cyclotomic, 0, 1);

  // Build the modulus using the cyclotomic polynomial representation
  build(phi, cyclotomic);
}

PrivateKey KeyParameters::GeneratePrivateKey() const {
  // Set finite field modulus to be q
  ZZ_pPush push;
  ZZ_p::init(q);

  // Create private key based off of small secret polynomial 
  ZZ_pX secret = conv<ZZ_pX>(random::UniformSample(n, ZZ(-1), ZZ(2)));

  return PrivateKey(conv<ZZX>(secret), *this);
}

PublicKey KeyParameters::GeneratePublicKey(const PrivateKey & priv) const {
  // Set finite field modulus to be q
  ZZ_pPush push;
  ZZ_p::init(q);

  // Compute a, where the coefficients are drawn uniformly from the finite field (integers mod q) 
  ZZ_pX a = conv<ZZ_pX>(random::UniformSample(n, q));

  // Copy private key parameters into polynomial over finite field
  ZZ_pX s = conv<ZZ_pX>(priv.GetS());

  // Draw error polynomial from discrete Gaussian distribution
  ZZ_pX e = conv<ZZ_pX>(random::GaussianSample(n));

  // Compute b = -(a * s + e)
  ZZ_pX b;
  MulMod(b, a, s, phi); 
  b += e;
  b = -b;

  // Create public key based off of a & b polynomials
  return PublicKey(conv<ZZX>(b), conv<ZZX>(a), *this);
}
