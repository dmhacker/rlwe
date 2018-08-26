#include "fv.hpp"
#include "sampling.hpp"
#include "defines.hpp"

#include <NTL/ZZ_pX.h>
#include <cassert>

using namespace rlwe;
using namespace rlwe::fv;

KeyParameters::KeyParameters(long n, ZZ q, ZZ t) :
  KeyParameters(n, q, t, DEFAULT_DECOMPOSITION_BIT_COUNT, DEFAULT_ERROR_STANDARD_DEVIATION) {}

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

  // Create probability matrix using sigma
  long bound_upper = std::floor(sigma * BOUNDS_SCALAR);
  probability_matrix.SetDims(bound_upper, PROBABILITY_MATRIX_PRECISION); 

  // Calculate some constants
  float variance = sigma * sigma;
  float pi2 = atan(1) * 8; 

  // Calculate probabilities and the total they sum to
  float total = 0;
  float probabilities[bound_upper];
  for (int i = 0; i < bound_upper; i++) {
    // Calculate probability using a Gaussian PDF 
    probabilities[i] = 1.0f / sqrt(pi2 * variance) * exp(-i * i / 2.0f / variance);

    // Positive numbers have a 50% chance to be made negative in sampling 
    // The probability of 0 must be lowered in order to compensate 
    if (i == 0)
      probabilities[i] /= 2;

    // Add it to the total
    total += probabilities[i];
  }

  float scaling_factor = 1.0f / total;
  for (int i = 0; i < bound_upper; i++) {
    // Calculate scaled version of probability (so everything sums to 1)
    float probability = probabilities[i] * scaling_factor; 

    // Fill in the row of the matrix
    float check_value = 0.5f;
    for (int j = 0; j < PROBABILITY_MATRIX_PRECISION; j++) {
      if (probability > check_value) {
        probability_matrix[i][j] = 1;
        probability -= check_value;
      }
      else {
        probability_matrix[i][j] = 0;
      }
      check_value /= 2;
    }
  }
}

PrivateKey fv::GeneratePrivateKey(const KeyParameters & params) {
  return PrivateKey(UniformSample(params.GetPolyModulusDegree(), ZZ(-1), ZZ(2)), params);
}

PublicKey fv::GeneratePublicKey(const PrivateKey & priv) {
  return GeneratePublicKey(priv, 
      UniformSample(priv.GetParameters().GetPolyModulusDegree(), priv.GetParameters().GetCoeffModulus()), 
      KnuthYaoSample(priv.GetParameters().GetPolyModulusDegree(), priv.GetParameters().GetProbabilityMatrix()));
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
  return PublicKey(Pair<ZZX, ZZX>(conv<ZZX>(b), conv<ZZX>(a)), params);
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
    ZZ_pX e = conv<ZZ_pX>(KnuthYaoSample(params.GetPolyModulusDegree(), params.GetProbabilityMatrix()));

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
