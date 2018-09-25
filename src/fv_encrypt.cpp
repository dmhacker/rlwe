#include "fv.h"
#include "sample.h"
#include "polyutil.h"

#include <NTL/ZZ_pX.h>
#include <cassert>

using namespace rlwe;
using namespace rlwe::fv;

void fv::Encrypt(Ciphertext & ctx, const Plaintext & ptx, const PublicKey & pub) {
  const KeyParameters & params = pub.GetParameters();
  assert(params == ctx.GetParameters());
  assert(params == ptx.GetParameters());

  // Set finite field modulus to be q
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  // Upscale plaintext to be in ciphertext ring
  ZZ_pX m = conv<ZZ_pX>(ptx.GetMessage()) * conv<ZZ_p>(params.GetPlainToCoeffScalar());

  // Draw u from uniform distribution over {-1, 0, 1}
  ZZ_pX u = conv<ZZ_pX>(UniformSample(params.GetPolyModulusDegree(), ZZ(-1), ZZ(2)));

  // Draw error polynomials from discrete Gaussian distribution
  ZZ_pX e1 = conv<ZZ_pX>(KnuthYaoSample(params.GetPolyModulusDegree(), params.GetProbabilityMatrix(), params.GetProbabilityMatrixRows())); 
  ZZ_pX e2 = conv<ZZ_pX>(KnuthYaoSample(params.GetPolyModulusDegree(), params.GetProbabilityMatrix(), params.GetProbabilityMatrixRows()));

  // Set up a temporary buffer to hold the results of multiplications
  ZZ_pX buffer;

  // Extract information from public key
  const Pair<ZZX, ZZX> & p = pub.GetValues();

  // c1 = p0 * u + e1 + m
  MulMod(buffer, conv<ZZ_pX>(p.a), u, params.GetPolyModulus());
  ZZ_pX c1 = buffer + e1 + m;

  // c2 = p1 * u + e2
  MulMod(buffer, conv<ZZ_pX>(p.b), u, params.GetPolyModulus());
  ZZ_pX c2 = buffer + e2;

  ctx.SetLength(2);
  ctx[0] = conv<ZZX>(c1);
  ctx[1] = conv<ZZX>(c2);
}

void fv::Decrypt(Plaintext & ptx, const Ciphertext & ctx, const PrivateKey & priv) {
  const KeyParameters & params = priv.GetParameters();
  assert(params == ptx.GetParameters());
  assert(params == ctx.GetParameters());

  // Set finite field modulus to be q
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  ZZ_pX secret = conv<ZZ_pX>(priv.GetSecret());

  // m = c0 + c1 * s + c2 * s^2 + ...
  ZZ_pX m;
  ZZ_pX buffer0;
  ZZ_pX buffer1;
  for (long i = 0; i < ctx.GetLength(); i++) {
    PowerMod(buffer0, secret, i, params.GetPolyModulus());
    MulMod(buffer1, conv<ZZ_pX>(ctx[i]), buffer0, params.GetPolyModulus());
    m += buffer1;
  }

  // Downscale m to be in plaintext ring
  ZZX message = conv<ZZX>(m);
  CenterCoeffs(message, message, params.GetCoeffModulus());
  RoundCoeffs(message, message, params.GetCoeffToPlainScalar(), params.GetPlainModulus());  

  ptx.SetMessage(message);
}

Ciphertext fv::Encrypt(const Plaintext & ptx, const PublicKey & pub) {
  Ciphertext ctx(pub.GetParameters());
  Encrypt(ctx, ptx, pub);
  return ctx;
}

Plaintext fv::Decrypt(const Ciphertext & ctx, const PrivateKey & priv) {
  Plaintext ptx(priv.GetParameters());
  Decrypt(ptx, ctx, priv);
  return ptx;
}
