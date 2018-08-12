#include "rlwe.hpp"

#include <NTL/ZZ_pX.h>
#include <NTL/GF2X.h>
#include <NTL/RR.h>
#include <cassert>
#include <random>

using namespace rlwe;

const float GAUSSIAN_STANDARD_DEVIATION = 3.192f;

ZZX random::UniformSample(long degree, long field_modulus, bool flip_bits) {
  ZZX poly;
  if (field_modulus == 2) {
    // If the finite field is modulo 2, we can use the GF2X class 
    poly = conv<ZZX>(random_GF2X(degree));
  }
  else {
    // Otherwise, we set a temporary modulus and use the ZZ_pX class
    ZZ_pPush push;
    ZZ_p::init(ZZ(field_modulus));
    poly = conv<ZZX>(random_ZZ_pX(degree));
  }

  // Iterate through each coefficient
  if (flip_bits) {
    for (long i = 0; i < degree; i++) {
      // 50% random chance that the coefficient will be negative
      if (rand() & 1) {
        SetCoeff(poly, i, -coeff(poly, i));
      }
    }
  }

  return poly;
}

// TODO: Replace with a high-quality discrete number generator (e.g. rejection sampler, Knuth-Yao algorithm)
ZZX random::GaussianSample(long degree, float standard_deviation) {
  std::random_device device;
  std::mt19937 spigot(device());
  std::normal_distribution<float> distribution(0.0f, standard_deviation);

  ZZX poly;
  for (long i = 0; i < degree; i++) {
    SetCoeff(poly, i, std::round(distribution(spigot)));
  }

  return poly;
}

KeyParameters::KeyParameters(long n0, NTL::ZZ q0, NTL::ZZ t0) : n(n0), q(q0), t(t0), q_div_t(q0 / t0) {
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
  // Create private key based off of secret polynomial drawn from polynomial ring over GF2 
  PrivateKey priv(random::UniformSample(n, 2, false), *this);
  return priv;
}

PublicKey KeyParameters::GeneratePublicKey(const PrivateKey & priv) const {
  // Set finite field modulus to be q
  ZZ_pPush push;
  ZZ_p::init(q);

  // Compute a, where the coefficients are drawn uniformly from the finite field (integers mod q) 
  ZZ_pX a = random_ZZ_pX(n);

  // Copy private key parameters into polynomial over finite field
  ZZ_pX s = conv<ZZ_pX>(priv.GetS());

  // Draw error polynomial from discrete Gaussian distribution
  ZZ_pX e = conv<ZZ_pX>(random::GaussianSample(n, GAUSSIAN_STANDARD_DEVIATION));

  // Compute b = -(a * s + e)
  ZZ_pX b;
  MulMod(b, a, s, phi);
  b += e;
  b = -b;

  // Create public key based off of a & b polynomials
  PublicKey pub(conv<ZZX>(b), conv<ZZX>(a), *this);
  return pub;
}

Ciphertext PublicKey::Encrypt(ZZX plaintext) {
  // Set finite field modulus to be q
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  // Upscale plaintext to be in ciphertext ring
  ZZ_pX m = conv<ZZ_pX>(plaintext) * conv<ZZ_p>(params.GetPlainToCoeffScalar());

  // Draw u from GF2 (coefficients are in integers mod 2)
  ZZ_pX u = conv<ZZ_pX>(random::UniformSample(params.GetPolyModulusDegree(), 2, true));

  // Draw error polynomials from discrete Gaussian distribution
  ZZ_pX e1 = conv<ZZ_pX>(random::GaussianSample(params.GetPolyModulusDegree(), GAUSSIAN_STANDARD_DEVIATION));
  ZZ_pX e2 = conv<ZZ_pX>(random::GaussianSample(params.GetPolyModulusDegree(), GAUSSIAN_STANDARD_DEVIATION));

  // Set up a temporary buffer to hold the results of multiplications
  ZZ_pX buffer;

  // c1 = p0 * u + e1 + m
  MulMod(buffer, conv<ZZ_pX>(p0), u, params.GetPolyModulus());
  ZZ_pX c1 = buffer + e1 + m;

  // c2 = p1 * u + e2
  MulMod(buffer, conv<ZZ_pX>(p1), u, params.GetPolyModulus());
  ZZ_pX c2 = buffer + e2;

  Ciphertext ciphertext(conv<ZZX>(c1), conv<ZZX>(c2));
  return ciphertext;
}

ZZX PrivateKey::Decrypt(Ciphertext ciphertext) {
  // Set finite field modulus to be q
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  // m = c1 + c2 * s
  ZZ_pX m;
  MulMod(m, conv<ZZ_pX>(ciphertext.GetC1()), conv<ZZ_pX>(s), params.GetPolyModulus());
  m += conv<ZZ_pX>(ciphertext.GetC0());

  // Downscale m to be in plaintext ring
  ZZX plaintext = conv<ZZX>(m) * params.GetPlainModulus();
  for (long i = 0; i < params.GetPolyModulusDegree(); i++) {
    RR rounded_coefficient = round(conv<RR>(coeff(plaintext, i)) / conv<RR>(params.GetCoeffModulus()));
    SetCoeff(plaintext, i, conv<ZZ>(rounded_coefficient));
  }

  return plaintext; 
}
