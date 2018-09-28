#include "newhope.h"
#include "sample.h"

#include <cassert>

using namespace rlwe::newhope;

KeyParameters::KeyParameters() : 
  KeyParameters(DEFAULT_POLY_MODULUS_DEGREE, ZZ(DEFAULT_COEFF_MODULUS), 
      DEFAULT_ERROR_STANDARD_DEVIATION) {}
        
KeyParameters::KeyParameters(size_t n, const ZZ & q) : 
  KeyParameters(n, q, DEFAULT_ERROR_STANDARD_DEVIATION) {}

KeyParameters::KeyParameters(size_t n, const ZZ & q, float sigma) : 
  n(n), q(q), sigma(sigma) {
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
