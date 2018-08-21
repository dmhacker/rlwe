#include "rlwe.hpp"

#include <cassert>
#include <NTL/ZZ_pX.h>

using namespace rlwe;

KeyParameters::KeyParameters(long n, ZZ q, ZZ t, long log_w, float sigma) : 
  n(n), q(q), t(t), log_w(log_w), sigma(sigma),
  delta(q / t), downscale(conv<RR>(t) / conv<RR>(q))
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

  // Calculate decomposition base and mask
  power2(w, log_w);
  w_mask = w - 1; 
  l = floor(log(q) / log(w));
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
  // Assert that private key parameters match up 
  assert(*this == priv.GetParameters());

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

EvaluationKey KeyParameters::GenerateEvaluationKey(const PrivateKey & priv, long level) const {
  // Assert that private key parameters match up 
  assert(*this == priv.GetParameters());

  // Set finite field modulus to be q 
  ZZ_pPush push;
  ZZ_p::init(q);

  // Copy private key parameters into polynomial over finite field
  ZZ_pX s = conv<ZZ_pX>(priv.GetS());

  // Compute s^(level)
  ZZ_pX s_level;
  PowerMod(s_level, s, level, phi);

  // Set up vector of pairs of polynomials
  Vec<Pair<ZZX, ZZX>> r;
  r.SetLength(l + 1);

  // Create temporary base
  ZZ_p tmp_w(1);

  for (long i = 0; i <= l; i++) {
    // Compute a, where the coefficients are drawn uniformly from the finite field (integers mod q) 
    ZZ_pX a = conv<ZZ_pX>(random::UniformSample(n, q));

    // Draw error polynomial from discrete Gaussian distribution
    ZZ_pX e = conv<ZZ_pX>(random::GaussianSample(n, sigma));

    // Compute b = -(a * s + e)
    ZZ_pX b;
    MulMod(b, a, s, phi); 
    b += e;
    b = -b + tmp_w * s_level;

    // Save b, a as pair in evaluation key
    r[i] = Pair<ZZX, ZZX>(conv<ZZX>(b), conv<ZZX>(a)); 

    // Right shift by the word size (e.g. multiply by the base)
    tmp_w *= conv<ZZ_p>(w);
  }

  return EvaluationKey(r, level, *this);
}
