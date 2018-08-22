#include "catch.hpp"
#include "../src/rlwe.hpp"
#include "../src/sampling.hpp"

#include <NTL/ZZ_pX.h>

TEST_CASE("FV-style homomorphic addition") {
  // Set up parameters
  rlwe::KeyParameters params(1024, 12289, 2);  

  // Compute keys
  rlwe::PrivateKey priv = params.GeneratePrivateKey();
  rlwe::PublicKey pub = params.GeneratePublicKey(priv);

  // Generate two random plaintexts
  rlwe::Plaintext pt1(rlwe::UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()), params);
  rlwe::Plaintext pt2(rlwe::UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()), params);

  // Convert both to ciphertexts 
  rlwe::Ciphertext ct1 = pub.Encrypt(pt1);
  rlwe::Ciphertext ct2 = pub.Encrypt(pt2);

  // Perform homomorphic addition
  rlwe::Ciphertext ct = ct1 + ct2;

  // Decrypt resultant ciphertext
  rlwe::Plaintext pt = priv.Decrypt(ct);

  // Compute the additions in the plaintext ring 
  ZZ_pPush push;
  ZZ_p::init(params.GetPlainModulus());
  ZZ_pX m_p = conv<ZZ_pX>(pt1.GetMessage()) + conv<ZZ_pX>(pt2.GetMessage());
  ZZX m = conv<ZZX>(m_p);

  REQUIRE(pt.GetMessage() == m);
}

