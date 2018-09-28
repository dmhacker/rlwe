#include "catch.hpp"
#include "fv.h"
#include "sample.h"

#include <NTL/ZZ_pX.h>

using namespace rlwe;
using namespace rlwe::fv;

TEST_CASE("Homomorphic multiplication") {
  // Set up parameters
  KeyParameters params(1024, ZZ(1152921504606830600ULL), ZZ(7));  

  // Compute keys
  PrivateKey priv = GeneratePrivateKey(params); 
  PublicKey pub = GeneratePublicKey(priv);

  // Generate two random plaintexts
  Plaintext ptx1(params);
  ptx1.SetMessage(UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()));
  Plaintext ptx2(params);
  ptx2.SetMessage(UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()));

  // Convert both to ciphertexts 
  Ciphertext ctx1 = Encrypt(ptx1, pub);
  Ciphertext ctx2 = Encrypt(ptx2, pub);

  // Perform homomorphic multiplication 
  Ciphertext ctx = ctx1 * ctx2;

  // Decrypt resultant ciphertext
  Plaintext ptx = Decrypt(ctx, priv);

  // Compute the multiplications in the plaintext ring 
  ZZ_pPush push;
  ZZ_p::init(params.GetPlainModulus());
  ZZ_pX m_p;
  MulMod(m_p, conv<ZZ_pX>(ptx1.GetMessage()), conv<ZZ_pX>(ptx2.GetMessage()), params.GetPolyModulus());
  ZZX m = conv<ZZX>(m_p);

  REQUIRE(ptx.GetMessage() == m);
}

TEST_CASE("Relinearization version 1") {
  // Set up parameters
  KeyParameters params(1024, ZZ(1152921504606830600ULL), ZZ(7));  

  // Compute keys
  PrivateKey priv = GeneratePrivateKey(params);
  PublicKey pub = GeneratePublicKey(priv); 
  EvaluationKey elk = GenerateEvaluationKey(priv, 2); 

  // Generate two random plaintexts
  Plaintext ptx1(params);
  ptx1.SetMessage(UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()));
  Plaintext ptx2(params);
  ptx2.SetMessage(UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()));

  // Convert both to ciphertexts 
  Ciphertext ctx1 = Encrypt(ptx1, pub);
  Ciphertext ctx2 = Encrypt(ptx2, pub);

  // Perform homomorphic multiplication 
  Ciphertext ctx = ctx1 * ctx2;
  REQUIRE(ctx.GetLength() == 3);

  // Relinearize resultant ciphertext
  ctx.Relinearize(elk);
  REQUIRE(ctx.GetLength() == 2);

  // Decrypt resultant ciphertext
  Plaintext ptx = Decrypt(ctx, priv);

  // Compute the multiplications in the plaintext ring 
  ZZ_pPush push;
  ZZ_p::init(params.GetPlainModulus());
  ZZ_pX m_p;
  MulMod(m_p, conv<ZZ_pX>(ptx1.GetMessage()), conv<ZZ_pX>(ptx2.GetMessage()), params.GetPolyModulus());
  ZZX m = conv<ZZX>(m_p);

  REQUIRE(ptx.GetMessage() == m);
}
