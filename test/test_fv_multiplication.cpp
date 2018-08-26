#include "catch.hpp"
#include "../src/fv.h"
#include "../src/sampling.h"

#include <NTL/ZZ_pX.h>

using namespace rlwe;
using namespace rlwe::fv;

TEST_CASE("Homomorphic multiplication") {
  // Set up parameters
  KeyParameters params(1024, conv<ZZ>("34359724033"), ZZ(2));  

  // Compute keys
  PrivateKey priv = GeneratePrivateKey(params); 
  PublicKey pub = GeneratePublicKey(priv);

  // Generate two random plaintexts
  Plaintext pt1(UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()), params);
  Plaintext pt2(UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()), params);

  // Convert both to ciphertexts 
  Ciphertext ct1 = Encrypt(pt1, pub);
  Ciphertext ct2 = Encrypt(pt2, pub);

  // Perform homomorphic multiplication 
  Ciphertext ct = ct1 * ct2;

  // Decrypt resultant ciphertext
  Plaintext pt = Decrypt(ct, priv);

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
  KeyParameters params(2048, conv<ZZ>("1152921504606830600"), ZZ(2));  

  // Compute keys
  PrivateKey priv = GeneratePrivateKey(params);
  PublicKey pub = GeneratePublicKey(priv); 
  EvaluationKey elk = GenerateEvaluationKey(priv, 2); 

  // Generate two random plaintexts
  Plaintext pt1(UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()), params);
  Plaintext pt2(UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()), params);

  // Convert both to ciphertexts 
  Ciphertext ct1 = Encrypt(pt1, pub);
  Ciphertext ct2 = Encrypt(pt2, pub);

  // Perform homomorphic multiplication 
  Ciphertext ct = ct1 * ct2;
  REQUIRE(ct.GetLength() == 3);

  // Relinearize resultant ciphertext
  ct.Relinearize(elk);
  REQUIRE(ct.GetLength() == 2);

  // Decrypt resultant ciphertext
  Plaintext pt = Decrypt(ct, priv);

  // Compute the multiplications in the plaintext ring 
  ZZ_pPush push;
  ZZ_p::init(params.GetPlainModulus());
  ZZ_pX m_p;
  MulMod(m_p, conv<ZZ_pX>(pt1.GetMessage()), conv<ZZ_pX>(pt2.GetMessage()), params.GetPolyModulus());
  ZZX m = conv<ZZX>(m_p);

  REQUIRE(pt.GetMessage() == m);
}
