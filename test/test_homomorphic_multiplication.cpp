#include "catch.hpp"
#include "../src/rlwe.hpp"

#include <NTL/ZZ_pX.h>

TEST_CASE("FV-style homomorphic multiplication") {
  // Set up parameters
  rlwe::KeyParameters params(1024, 34359724033, 2);  

  // Compute keys
  rlwe::PrivateKey priv = params.GeneratePrivateKey();
  rlwe::PublicKey pub = params.GeneratePublicKey(priv);

  // Generate two random plaintexts
  rlwe::Plaintext pt1(rlwe::random::UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()), params);
  rlwe::Plaintext pt2(rlwe::random::UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()), params);

  // Convert both to ciphertexts 
  rlwe::Ciphertext ct1 = pub.Encrypt(pt1);
  rlwe::Ciphertext ct2 = pub.Encrypt(pt2);

  // Perform homomorphic multiplication 
  rlwe::Ciphertext ct = ct1 * ct2;

  // Decrypt resultant ciphertext
  rlwe::Plaintext pt = priv.Decrypt(ct);

  // Compute the multiplications in the plaintext ring 
  ZZ_pPush push;
  ZZ_p::init(params.GetPlainModulus());
  ZZ_pX m_p;
  MulMod(m_p, conv<ZZ_pX>(pt1.GetM()), conv<ZZ_pX>(pt2.GetM()), params.GetPolyModulus());
  ZZX m = conv<ZZX>(m_p);

  REQUIRE(pt.GetM() == m);
}

TEST_CASE("FV-style relinearization") {
  // Set up parameters
  rlwe::KeyParameters params(2048, 1152921504606830600, 2);  

  // Compute keys
  rlwe::PrivateKey priv = params.GeneratePrivateKey();
  rlwe::PublicKey pub = params.GeneratePublicKey(priv);
  rlwe::EvaluationKey elk = params.GenerateEvaluationKey(priv, 2);

  // Generate two random plaintexts
  rlwe::Plaintext pt1(rlwe::random::UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()), params);
  rlwe::Plaintext pt2(rlwe::random::UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()), params);

  // Convert both to ciphertexts 
  rlwe::Ciphertext ct1 = pub.Encrypt(pt1);
  rlwe::Ciphertext ct2 = pub.Encrypt(pt2);

  // Perform homomorphic multiplication 
  rlwe::Ciphertext ct = ct1 * ct2;
  REQUIRE(ct.GetLength() == 3);

  // Relinearize resultant ciphertext
  ct.Relinearize(elk);
  REQUIRE(ct.GetLength() == 2);

  // Decrypt resultant ciphertext
  rlwe::Plaintext pt = priv.Decrypt(ct);

  // Compute the multiplications in the plaintext ring 
  ZZ_pPush push;
  ZZ_p::init(params.GetPlainModulus());
  ZZ_pX m_p;
  MulMod(m_p, conv<ZZ_pX>(pt1.GetM()), conv<ZZ_pX>(pt2.GetM()), params.GetPolyModulus());
  ZZX m = conv<ZZX>(m_p);

  REQUIRE(pt.GetM() == m);
}
