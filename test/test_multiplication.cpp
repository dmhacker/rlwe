#include "catch.hpp"
#include "../src/rlwe.hpp"

#include <NTL/ZZ_pX.h>

TEST_CASE("FV-style homomorphic multiplication") {
  // Set up parameters
  rlwe::KeyParameters params(16, 12289, 3);  

  // Compute keys
  rlwe::PrivateKey priv = params.GeneratePrivateKey();
  rlwe::PublicKey pub = params.GeneratePublicKey(priv);
  rlwe::EvaluationKey elk = params.GenerateEvaluationKey(priv);

  // Generate two random plaintexts
  rlwe::Plaintext pt1(rlwe::random::UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()), params);
  rlwe::Plaintext pt2(rlwe::random::UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()), params);

  // Convert both to ciphertexts 
  rlwe::Ciphertext ct1 = pub.Encrypt(pt1);
  rlwe::Ciphertext ct2 = pub.Encrypt(pt2);

  // Perform homomorphic addition
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
