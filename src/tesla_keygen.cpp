#include "tesla.h"
#include "sampling.h"

#include <NTL/ZZ_pX.h>
#include <cassert>

using namespace rlwe;
using namespace rlwe::tesla;

KeyParameters::KeyParameters(long n, float sigma, long L, ZZ w, ZZ B, ZZ U, ZZ d, ZZ q) :
  KeyParameters(n, sigma, L, w, B, U, d, q, UniformSample(n, q), UniformSample(n, q)) {}

KeyParameters::KeyParameters(long n, float sigma, long L, ZZ w, ZZ B, ZZ U, ZZ d, ZZ q, ZZX a1, ZZX a2) :
  n(n), sigma(sigma), L(L), w(w), B(B), U(U), d(d), q(q), a(a1, a2),
  probability_matrix(KnuthYaoGaussianMatrix(sigma, L)) 
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

SigningKey tesla::GenerateSigningKey(const KeyParameters & params) {
  // Generate randomly sampled error polynomials
  // Note that we don't have to reject any error samples because the Knuth-Yao sampling method restricts the bound already
  ZZX e1 = KnuthYaoSample(params.GetPolyModulusDegree(), params.GetProbabilityMatrix());
  ZZX e2 = KnuthYaoSample(params.GetPolyModulusDegree(), params.GetProbabilityMatrix());

  // Sample secret polynomial from same Gaussian distribution
  ZZX s = KnuthYaoSample(params.GetPolyModulusDegree(), params.GetProbabilityMatrix());

  return SigningKey(s, e1, e2, params); 
}

VerificationKey tesla::GenerateVerificationKey(const SigningKey & signer) {
  const KeyParameters & params = signer.GetParameters();

  // Setup global coefficient modulus 
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  // Perform conversions to ZZ_p-reduced polynomials
  ZZ_pX s =  conv<ZZ_pX>(signer.GetSecret());
  ZZ_pX e1 = conv<ZZ_pX>(signer.GetErrorValues().a); 
  ZZ_pX e2 = conv<ZZ_pX>(signer.GetErrorValues().b); 
  ZZ_pX a1 = conv<ZZ_pX>(params.GetPolyConstants().a);
  ZZ_pX a2 = conv<ZZ_pX>(params.GetPolyConstants().b);

  // t1 = a1 * s + e1 
  ZZ_pX t1;
  MulMod(t1, a1, s, params.GetPolyModulus());
  t1 += e1; 

  // t2 = a2 * s + e2
  ZZ_pX t2;
  MulMod(t2, a2, s, params.GetPolyModulus());
  t2 += e2;

  return VerificationKey(conv<ZZX>(t1), conv<ZZX>(t2), params);
}
