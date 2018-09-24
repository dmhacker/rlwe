#include "catch.hpp"
#include "fv.h" 
#include "sample.h"

#include <NTL/ZZ_pX.h>

using namespace rlwe;
using namespace rlwe::fv;

TEST_CASE("Homomorphic addition") {
  // Set up parameters
  KeyParameters params(1024, 12289, 2);  

  // Compute keys
  PrivateKey priv = GeneratePrivateKey(params);
  PublicKey pub = GeneratePublicKey(priv);

  // Generate two random plaintexts
  Plaintext pt1(UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()), params);
  Plaintext pt2(UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()), params);

  // Convert both to ciphertexts 
  Ciphertext ct1 = Encrypt(pt1, pub);
  Ciphertext ct2 = Encrypt(pt2, pub);

  // Perform homomorphic addition
  Ciphertext ct = ct1 + ct2;

  // Decrypt resultant ciphertext
  Plaintext pt = Decrypt(ct, priv);

  // Compute the additions in the plaintext ring 
  ZZ_pPush push;
  ZZ_p::init(params.GetPlainModulus());
  ZZ_pX m_p = conv<ZZ_pX>(pt1.GetMessage()) + conv<ZZ_pX>(pt2.GetMessage());
  ZZX m = conv<ZZX>(m_p);

  REQUIRE(pt.GetMessage() == m);
}

