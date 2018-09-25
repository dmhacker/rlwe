#include "tesla.h"
#include "sample.h"

#include <NTL/ZZ_pX.h>
#include <cassert>
#include <algorithm>    
#include <vector>      

using namespace rlwe;
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

bool CheckError(const ZZX & e, long w, long L) {
  // Sort all of the coefficients in descending order
  std::vector<ZZ> coeffs;
  for (int i = 0; i <= deg(e); i++) {
    coeffs.push_back(coeff(e, i));
  }
  std::sort(coeffs.begin(), coeffs.end());
  std::reverse(coeffs.begin(), coeffs.end());

  // Sum the top `w` coefficients 
  ZZ sum(0);
  for (int i = 0; i < w; i++) {
    sum += coeffs[i];
  }

  // Make sure that the sum is less than the given error bound
  return sum <= L;
}

void tesla::GenerateSigningKey(SigningKey & signer) {
  const KeyParameters & params = signer.GetParameters();

  // Generate error polynomial e1
  ZZX e1;
  bool check = false;
  while (!check) {
    e1 = KnuthYaoSample(params.GetPolyModulusDegree(), params.GetProbabilityMatrix(), params.GetProbabilityMatrixRows());
    check = CheckError(e1, params.GetEncodingWeight(), params.GetErrorBound());
  }

  // Generate error polynomial e2
  ZZX e2;
  check = false;
  while (!check) {
    e2 = KnuthYaoSample(params.GetPolyModulusDegree(), params.GetProbabilityMatrix(), params.GetProbabilityMatrixRows());
    check = CheckError(e2, params.GetEncodingWeight(), params.GetErrorBound());
  }

  // Set error values if they have passed all checks
  signer.SetErrors(e1, e2);

  // Sample secret polynomial from same Gaussian distribution
  signer.SetSecret(KnuthYaoSample(
        params.GetPolyModulusDegree(), 
        params.GetProbabilityMatrix(), 
        params.GetProbabilityMatrixRows()));
}

void tesla::GenerateVerificationKey(VerificationKey & verif, const SigningKey & signer) {
  const KeyParameters & params = signer.GetParameters();
  assert(params == verif.GetParameters()); 

  // Setup global coefficient modulus 
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  // Perform conversions to ZZ_p-reduced polynomials
  ZZ_pX s =  conv<ZZ_pX>(signer.GetSecret());
  ZZ_pX e1 = conv<ZZ_pX>(signer.GetErrors().a); 
  ZZ_pX e2 = conv<ZZ_pX>(signer.GetErrors().b); 
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

  verif.SetValues(conv<ZZX>(t1), conv<ZZX>(t2));
}

SigningKey tesla::GenerateSigningKey(const KeyParameters & params) {
  SigningKey signer(params);
  GenerateSigningKey(signer);
  return signer;
}

VerificationKey tesla::GenerateVerificationKey(const SigningKey & signer) {
  VerificationKey verif(signer.GetParameters());
  GenerateVerificationKey(verif, signer);
  return verif;
}
