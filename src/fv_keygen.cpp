#include "fv.h"
#include "sample.h"

#include <NTL/ZZ_pX.h>
#include <cassert>

#define BOUNDS_SCALAR 6

using namespace rlwe;
using namespace rlwe::fv;

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

  // Generate probability matrix
  probability_matrix_rows = sigma * BOUNDS_SCALAR;
  probability_matrix = (char **) malloc(probability_matrix_rows * sizeof(char *));
  for (size_t i = 0; i < probability_matrix_rows; i++) {
    probability_matrix[i] = (char *) calloc(PROBABILITY_MATRIX_BYTE_PRECISION, sizeof(char));
  }
  KnuthYaoGaussianMatrix(probability_matrix, probability_matrix_rows, sigma); 
}

PrivateKey fv::GeneratePrivateKey(const KeyParameters & params) {
  return PrivateKey(UniformSample(params.GetPolyModulusDegree(), ZZ(-1), ZZ(2)), params);
}

PublicKey fv::GeneratePublicKey(const PrivateKey & priv) {
  return GeneratePublicKey(priv, 
      UniformSample(priv.GetParameters().GetPolyModulusDegree(), priv.GetParameters().GetCoeffModulus()), 
      KnuthYaoSample(priv.GetParameters().GetPolyModulusDegree(), priv.GetParameters().GetProbabilityMatrix(), priv.GetParameters().GetProbabilityMatrixRows()));
}

PublicKey fv::GeneratePublicKey(const PrivateKey & priv, const ZZX & shared_a, const ZZX & shared_e) { 
  const KeyParameters & params = priv.GetParameters();

  // Set finite field modulus to be q
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  // a is given; just copy it into a ZZ_pX object
  ZZ_pX a = conv<ZZ_pX>(shared_a);

  // Do the same with e
  ZZ_pX e = conv<ZZ_pX>(shared_e);

  // Copy private key parameters into polynomial over finite field
  ZZ_pX s = conv<ZZ_pX>(priv.GetSecret());

  // Compute b = -(a * s + e)
  ZZ_pX b;
  MulMod(b, a, s, params.GetPolyModulus()); 
  b += e;
  b = -b;

  // Create public key based off of a & b polynomials
  return PublicKey(conv<ZZX>(b), conv<ZZX>(a), params);
}

EvaluationKey fv::GenerateEvaluationKey(const PrivateKey & priv, long level) {
  const KeyParameters & params = priv.GetParameters();

  // Set finite field modulus to be q 
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  // Copy private key parameters into polynomial over finite field
  ZZ_pX s = conv<ZZ_pX>(priv.GetSecret());

  // Compute s^(level)
  ZZ_pX s_level;
  PowerMod(s_level, s, level, params.GetPolyModulus());

  // Set up vector of pairs of polynomials
  Vec<Pair<ZZX, ZZX>> r;
  r.SetLength(params.GetDecompositionTermCount() + 1);

  // Create temporary base
  ZZ_p tmp_w(1);

  for (long i = 0; i <= params.GetDecompositionTermCount(); i++) {
    // Compute a, where the coefficients are drawn uniformly from the finite field (integers mod q) 
    ZZ_pX a = conv<ZZ_pX>(UniformSample(params.GetPolyModulusDegree(), params.GetCoeffModulus()));

    // Draw error polynomial from discrete Gaussian distribution
    ZZ_pX e = conv<ZZ_pX>(KnuthYaoSample(params.GetPolyModulusDegree(), params.GetProbabilityMatrix(), params.GetProbabilityMatrixRows()));

    // Compute b = -(a * s + e)
    ZZ_pX b;
    MulMod(b, a, s, params.GetPolyModulus()); 
    b += e;
    b = -b + tmp_w * s_level;

    // Save b, a as pair in evaluation key
    r[i] = Pair<ZZX, ZZX>(conv<ZZX>(b), conv<ZZX>(a)); 

    // Right shift by the word size (e.g. multiply by the base)
    tmp_w *= conv<ZZ_p>(params.GetDecompositionBase());
  }

  return EvaluationKey(r, level, params);
}
