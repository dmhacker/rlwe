#include "tesla.h"
#include "sample.h"

#include <cassert>

using namespace rlwe::tesla;

KeyParameters::KeyParameters(long n, float sigma, long L, long w, ZZ B, ZZ U, long d, ZZ q) :
  KeyParameters(n, sigma, L, w, B, U, d, q, UniformSample(n, q), UniformSample(n, q)) {}

KeyParameters::KeyParameters(long n, float sigma, long L, long w, ZZ B, ZZ U, long d, ZZ q, ZZX a1, ZZX a2) :
  n(n), sigma(sigma), L(L), w(w), B(B), U(U), d(d), q(q), a(a1, a2), pow_2d(power_ZZ(2, d))
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
