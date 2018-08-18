#include "rlwe.hpp"

#include <cassert>
#include <NTL/ZZ_pX.h>

using namespace rlwe;

KeyParameters::KeyParameters(long n0, ZZ q0, ZZ t0, ZZ p0, float sigma0, float sigma_t0) : 
  n(n0), q(q0), t(t0), p(p0), 
  delta(q0 / t0), downscale(conv<RR>(t0) / conv<RR>(q0)), 
  sigma(sigma0), sigma_t(sigma_t0) 
{
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
  // Compute a, where the coefficients are drawn uniformly from the integers mod q 
  ZZX a = random::UniformSample(n, q);

  // Draw error polynomial from discrete Gaussian distribution
  ZZX e = random::GaussianSample(n, sigma);

  // Delegate to separate constructor now that a is known
  return KeyParameters::GeneratePublicKey(priv, a, e);
}

PublicKey KeyParameters::GeneratePublicKey(const PrivateKey & priv, const ZZX & a_random, const ZZX & e_random) const {
  // Set finite field modulus to be q
  ZZ_pPush push;
  ZZ_p::init(q);

  // a is given; just copy it into a ZZ_pX object
  ZZ_pX a = conv<ZZ_pX>(a_random);

  // Do the same with e
  ZZ_pX e = conv<ZZ_pX>(e_random);

  // Copy private key parameters into polynomial over finite field
  ZZ_pX s = conv<ZZ_pX>(priv.GetS());

  // Compute b = -(a * s + e)
  ZZ_pX b;
  MulMod(b, a, s, phi); 
  b += e;
  b = -b;

  // Create public key based off of a & b polynomials
  return PublicKey(conv<ZZX>(b), conv<ZZX>(a), *this);
}

// TODO: Redo with relinearization version 1
EvaluationKey KeyParameters::GenerateEvaluationKey(const PrivateKey & priv) const {
  // Set finite field modulus to be q
  ZZ_pPush push;
  ZZ_p::init(p * q);

  // Compute a, where the coefficients are drawn uniformly from the finite field (integers mod q) 
  ZZ_pX a = conv<ZZ_pX>(random::UniformSample(n, p * q));

  // Copy private key parameters into polynomial over finite field
  ZZ_pX s = conv<ZZ_pX>(priv.GetS());

  // Draw error polynomial from discrete Gaussian distribution
  ZZ_pX e = conv<ZZ_pX>(random::GaussianSample(n, sigma_t));

  // Compute b = -(a * s + e)
  ZZ_pX b;
  MulMod(b, a, s, phi); 
  b += e;
  b = -b;

  ZZ_pX buffer;
  MulMod(buffer, s, s, phi);
  buffer *= conv<ZZ_p>(p);
  b += buffer;

  return EvaluationKey(conv<ZZX>(b), conv<ZZX>(a), *this);
}
