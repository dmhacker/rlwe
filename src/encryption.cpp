#include "rlwe.hpp"
#include "sampling.hpp"
#include "util.hpp"

#include <NTL/ZZ_pX.h>
#include <NTL/RR.h>

using namespace rlwe;

Ciphertext PublicKey::Encrypt(const Plaintext & plaintext) const {
  // Set finite field modulus to be q
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  // Upscale plaintext to be in ciphertext ring
  ZZ_pX m = conv<ZZ_pX>(plaintext.GetMessage()) * conv<ZZ_p>(params.GetPlainToCoeffScalar());

  // Draw u from uniform distribution over {-1, 0, 1}
  ZZ_pX u = conv<ZZ_pX>(UniformSample(params.GetPolyModulusDegree(), ZZ(-1), ZZ(2)));

  // Draw error polynomials from discrete Gaussian distribution
  ZZ_pX e1 = conv<ZZ_pX>(GaussianSample(params.GetPolyModulusDegree(), params.GetErrorStandardDeviation())); 
  ZZ_pX e2 = conv<ZZ_pX>(GaussianSample(params.GetPolyModulusDegree(), params.GetErrorStandardDeviation()));

  // Set up a temporary buffer to hold the results of multiplications
  ZZ_pX buffer;

  // c1 = p0 * u + e1 + m
  MulMod(buffer, conv<ZZ_pX>(p.a), u, params.GetPolyModulus());
  ZZ_pX c1 = buffer + e1 + m;

  // c2 = p1 * u + e2
  MulMod(buffer, conv<ZZ_pX>(p.b), u, params.GetPolyModulus());
  ZZ_pX c2 = buffer + e2;

  return Ciphertext(conv<ZZX>(c1), conv<ZZX>(c2), params);
}

Plaintext PrivateKey::Decrypt(const Ciphertext & ciphertext) const {
  // Set finite field modulus to be q
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  ZZ_pX secret = conv<ZZ_pX>(s);

  // m = c0 + c1 * s + c2 * s^2 + ...
  ZZ_pX m;
  ZZ_pX buffer0;
  ZZ_pX buffer1;
  for (long i = 0; i < ciphertext.GetLength(); i++) {
    PowerMod(buffer0, secret, i, params.GetPolyModulus());
    MulMod(buffer1, conv<ZZ_pX>(ciphertext[i]), buffer0, params.GetPolyModulus());
    m += buffer1;
  }

  // Downscale m to be in plaintext ring
  ZZX plaintext = conv<ZZX>(m);
  CenterCoeffs(plaintext, params.GetCoeffModulus());
  ScaleCoeffs(plaintext, params.GetCoeffToPlainScalar(), params.GetPlainModulus());  

  return Plaintext(plaintext, params);
}
