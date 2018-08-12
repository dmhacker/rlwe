#include "rlwe.hpp"

#include <NTL/ZZ_pX.h>
#include <NTL/RR.h>

using namespace rlwe;

void CenterCoefficients(ZZX & poly, ZZ mod) {
  ZZ center_point = mod / 2;
  for (long i = 0; i <= deg(poly); i++) {
    ZZ coefficient = coeff(poly, i);
    if (coefficient > center_point) {
      SetCoeff(poly, i, coefficient - mod);
    }   
  }
}

void DownscaleCoefficients(ZZX & poly, ZZ t, ZZ q) {
  RR scalar = conv<RR>(t) / conv<RR>(q);
  for (long i = 0; i <= deg(poly); i++) {
    RR rounded_coefficient = round(conv<RR>(coeff(poly, i)) * scalar); 
    SetCoeff(poly, i, conv<ZZ>(rounded_coefficient) % t);
  }
}

Ciphertext PublicKey::Encrypt(const Plaintext & plaintext) const {
  // Set finite field modulus to be q
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  // Upscale plaintext to be in ciphertext ring
  ZZ_pX m = conv<ZZ_pX>(plaintext.GetM()) * conv<ZZ_p>(params.GetPlainToCoeffScalar());

  // Draw u from GF2 (coefficients are in integers mod 2)
  ZZ_pX u = conv<ZZ_pX>(random::UniformSample(params.GetPolyModulusDegree(), ZZ(2), true));

  // Draw error polynomials from discrete Gaussian distribution
  ZZ_pX e1 = conv<ZZ_pX>(random::GaussianSample(params.GetPolyModulusDegree())); 
  ZZ_pX e2 = conv<ZZ_pX>(random::GaussianSample(params.GetPolyModulusDegree()));

  // Set up a temporary buffer to hold the results of multiplications
  ZZ_pX buffer;

  // c1 = p0 * u + e1 + m
  MulMod(buffer, conv<ZZ_pX>(p0), u, params.GetPolyModulus());
  ZZ_pX c1 = buffer + e1 + m;

  // c2 = p1 * u + e2
  MulMod(buffer, conv<ZZ_pX>(p1), u, params.GetPolyModulus());
  ZZ_pX c2 = buffer + e2;

  Ciphertext ciphertext(conv<ZZX>(c1), conv<ZZX>(c2));
  return ciphertext;
}

Plaintext PrivateKey::Decrypt(const Ciphertext & ciphertext) const {
  // Set finite field modulus to be q
  ZZ_pPush push;
  ZZ_p::init(params.GetCoeffModulus());

  // m = c1 + c2 * s
  ZZ_pX m;
  MulMod(m, conv<ZZ_pX>(ciphertext.GetC1()), conv<ZZ_pX>(s), params.GetPolyModulus());
  m += conv<ZZ_pX>(ciphertext.GetC0());

  // Downscale m to be in plaintext ring
  ZZX plaintext = conv<ZZX>(m);
  CenterCoefficients(plaintext, params.GetCoeffModulus());
  DownscaleCoefficients(plaintext, params.GetPlainModulus(), params.GetCoeffModulus());  

  return Plaintext(plaintext);
}
