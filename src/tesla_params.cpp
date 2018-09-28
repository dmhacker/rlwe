#include "tesla.h"
#include "sample.h"

#include <cassert>

using namespace rlwe::tesla;

// Mainly used for testing; not recommended for actual usage 
KeyParameters::KeyParameters() : 
  KeyParameters(
      UniformSample(DEFAULT_POLY_MODULUS_DEGREE, ZZ(DEFAULT_COEFF_MODULUS)), 
      UniformSample(DEFAULT_POLY_MODULUS_DEGREE, ZZ(DEFAULT_COEFF_MODULUS))) {}

// 128-bit security, parameters recommended by the original paper
KeyParameters::KeyParameters(const ZZX & a1, const ZZX & a2) : 
  KeyParameters(a1, a2, 
      DEFAULT_POLY_MODULUS_DEGREE, DEFAULT_ERROR_STANDARD_DEVIATION, 
      ZZ(DEFAULT_ERROR_BOUND), DEFAULT_ENCODING_WEIGHT, 
      ZZ(DEFAULT_SIGNATURE_BOUND), ZZ(DEFAULT_SIGNATURE_BOUND_ADJUSTMENT), 
      DEFAULT_LEAST_SIGNIFICANT_BITS, ZZ(DEFAULT_COEFF_MODULUS)) {}

KeyParameters::KeyParameters(const ZZX & a1, const ZZX & a2, 
    size_t n, float sigma, const ZZ & L, uint32_t w, 
    const ZZ & B, const ZZ & U, uint32_t d, const ZZ & q) :
  a(a1, a2), n(n), sigma(sigma), L(L), w(w), B(B), U(U), d(d), q(q), pow_2d(power_ZZ(2, d))
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

  // Generate probability matrix
  pmat_rows = sigma * PROBABILITY_MATRIX_BOUNDS_SCALAR;
  pmat = KnuthYaoGaussianMatrix(pmat_rows, sigma); 
}
