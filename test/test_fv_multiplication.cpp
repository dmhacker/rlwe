#include "catch.hpp"
#include "../src/fv.hpp"
#include "../src/sampling.hpp"

#include <NTL/ZZ_pX.h>

using namespace rlwe;
using namespace rlwe::fv;

TEST_CASE("Homomorphic multiplication") {
  // Set up parameters
  KeyParameters params(1024, 34359724033, 2);  

  // Compute keys
  PrivateKey priv = params.GeneratePrivateKey();
  PublicKey pub = params.GeneratePublicKey(priv);

  // Generate two random plaintexts
  Plaintext pt1(UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()), params);
  Plaintext pt2(UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()), params);

  // Convert both to ciphertexts 
  Ciphertext ct1 = pub.Encrypt(pt1);
  Ciphertext ct2 = pub.Encrypt(pt2);

  // Perform homomorphic multiplication 
  Ciphertext ct = ct1 * ct2;

  // Decrypt resultant ciphertext
  Plaintext pt = priv.Decrypt(ct);

  // Compute the multiplications in the plaintext ring 
  ZZ_pPush push;
  ZZ_p::init(params.GetPlainModulus());
  ZZ_pX m_p;
  MulMod(m_p, conv<ZZ_pX>(pt1.GetMessage()), conv<ZZ_pX>(pt2.GetMessage()), params.GetPolyModulus());
  ZZX m = conv<ZZX>(m_p);

  REQUIRE(pt.GetMessage() == m);
}

TEST_CASE("Relinearization version 1") {
  // Set up parameters
  KeyParameters params(2048, 1152921504606830600, 2);  

  // Compute keys
  PrivateKey priv = params.GeneratePrivateKey();
  PublicKey pub = params.GeneratePublicKey(priv);
  EvaluationKey elk = params.GenerateEvaluationKey(priv, 2);

  // Generate two random plaintexts
  Plaintext pt1(UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()), params);
  Plaintext pt2(UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()), params);

  // Convert both to ciphertexts 
  Ciphertext ct1 = pub.Encrypt(pt1);
  Ciphertext ct2 = pub.Encrypt(pt2);

  // Perform homomorphic multiplication 
  Ciphertext ct = ct1 * ct2;
  REQUIRE(ct.GetLength() == 3);

  // Relinearize resultant ciphertext
  ct.Relinearize(elk);
  REQUIRE(ct.GetLength() == 2);

  // Decrypt resultant ciphertext
  Plaintext pt = priv.Decrypt(ct);

  // Compute the multiplications in the plaintext ring 
  ZZ_pPush push;
  ZZ_p::init(params.GetPlainModulus());
  ZZ_pX m_p;
  MulMod(m_p, conv<ZZ_pX>(pt1.GetMessage()), conv<ZZ_pX>(pt2.GetMessage()), params.GetPolyModulus());
  ZZX m = conv<ZZX>(m_p);

  REQUIRE(pt.GetMessage() == m);
}
