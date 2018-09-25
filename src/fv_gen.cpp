#include "fv.h"
#include "sample.h"

#include <cassert>

using namespace rlwe;
using namespace rlwe::fv;

void fv::GeneratePrivateKey(PrivateKey & priv) {
  const KeyParameters & params = priv.GetParameters();
  priv.SetSecret(UniformSample(params.GetPolyModulusDegree(), ZZ(-1), ZZ(2)));
}

void fv::GeneratePublicKey(PublicKey & pub, const PrivateKey & priv) {
  const KeyParameters & params = priv.GetParameters();
  assert(params == pub.GetParameters());
  
  // Set finite field modulus to be q
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  // Generate a uniformly
  ZZX a = UniformSample(params.GetPolyModulusDegree(), params.GetCoeffModulus());
  ZZ_pX a_p = conv<ZZ_pX>(a);

  // Sample e from a Gaussian distribution
  ZZ_pX e_p = conv<ZZ_pX>(
      KnuthYaoSample(params.GetPolyModulusDegree(), 
        params.GetProbabilityMatrix(), 
        params.GetProbabilityMatrixRows()));

  // Copy private key parameters into polynomial over finite field
  ZZ_pX s_p = conv<ZZ_pX>(priv.GetSecret());

  // Compute b = -(a * s + e)
  ZZ_pX b_p;
  MulMod(b_p, a_p, s_p, params.GetPolyModulus()); 
  b_p += e_p;
  b_p = -b_p;

  // Create public key based off of a & b polynomials
  pub.SetValues(conv<ZZX>(b_p), a);
}

void fv::GeneratePublicKey(PublicKey & pub, const PrivateKey & priv, const ZZX & a, const ZZX & e) { 
  const KeyParameters & params = priv.GetParameters();
  assert(params == pub.GetParameters());

  // Set finite field modulus to be q
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  // a is given; just copy it into a ZZ_pX object
  ZZ_pX a_p = conv<ZZ_pX>(a);

  // Do the same with e
  ZZ_pX e_p = conv<ZZ_pX>(e);

  // Copy private key parameters into polynomial over finite field
  ZZ_pX s_p = conv<ZZ_pX>(priv.GetSecret());

  // Compute b = -(a * s + e)
  ZZ_pX b_p;
  MulMod(b_p, a_p, s_p, params.GetPolyModulus()); 
  b_p += e_p;
  b_p = -b_p;

  // Create public key based off of a & b polynomials
  pub.SetValues(conv<ZZX>(b_p), a);
}

void fv::GenerateEvaluationKey(EvaluationKey & elk, const PrivateKey & priv, long level) {
  const KeyParameters & params = priv.GetParameters();
  assert(params == elk.GetParameters()); 

  // Set finite field modulus to be q 
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  // Copy private key parameters into polynomial over finite field
  ZZ_pX s = conv<ZZ_pX>(priv.GetSecret());

  // Compute s^(level)
  ZZ_pX s_level;
  PowerMod(s_level, s, level, params.GetPolyModulus());

  // Set up evaluation key 
  elk.SetLevel(level);
  elk.SetLength(params.GetDecompositionTermCount() + 1);

  // Create temporary base
  ZZ_p tmp_w(1);

  for (long i = 0; i <= params.GetDecompositionTermCount(); i++) {
    // Compute a, where the coefficients are drawn uniformly from the finite field (integers mod q) 
    ZZ_pX a = conv<ZZ_pX>(
        UniformSample(params.GetPolyModulusDegree(), params.GetCoeffModulus()));

    // Draw error polynomial from discrete Gaussian distribution
    ZZ_pX e = conv<ZZ_pX>(
        KnuthYaoSample(params.GetPolyModulusDegree(), 
          params.GetProbabilityMatrix(), 
          params.GetProbabilityMatrixRows()));

    // Compute b = -(a * s + e)
    ZZ_pX b;
    MulMod(b, a, s, params.GetPolyModulus()); 
    b += e;
    b = -b + tmp_w * s_level;

    // Save b, a as pair in evaluation key
    elk[i] = Pair<ZZX, ZZX>(conv<ZZX>(b), conv<ZZX>(a)); 

    // Right shift by the word size (e.g. multiply by the base)
    tmp_w *= conv<ZZ_p>(params.GetDecompositionBase());
  }
}

PrivateKey fv::GeneratePrivateKey(const KeyParameters & params) {
  PrivateKey priv(params);
  GeneratePrivateKey(priv);
  return priv;
}

PublicKey fv::GeneratePublicKey(const PrivateKey & priv) {
  const KeyParameters & params = priv.GetParameters();
  PublicKey pub(params);
  GeneratePublicKey(pub, priv);
  return pub;
}

PublicKey fv::GeneratePublicKey(const PrivateKey & priv, const ZZX & a, const ZZX & e) {
  const KeyParameters & params = priv.GetParameters();
  PublicKey pub(params);
  GeneratePublicKey(pub, priv, a, e);
  return pub;
}

EvaluationKey fv::GenerateEvaluationKey(const PrivateKey & priv, long level) {
  const KeyParameters & params = priv.GetParameters();
  EvaluationKey elk(params);
  GenerateEvaluationKey(elk, priv, level);
  return elk;
}
