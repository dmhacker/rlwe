#include "catch.hpp"
#include "../src/fv.hpp"
#include "../src/sampling.hpp"

#include <NTL/ZZ_pX.h>

using namespace rlwe;
using namespace rlwe::fv;

TEST_CASE("Homomorphic addition") {
  // Set up parameters
  KeyParameters params(1024, 12289, 2);  

  // Compute keys
  PrivateKey priv = params.GeneratePrivateKey();
  PublicKey pub = params.GeneratePublicKey(priv);

  // Generate two random plaintexts
  Plaintext pt1(UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()), params);
  Plaintext pt2(UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()), params);

  // Convert both to ciphertexts 
  Ciphertext ct1 = pub.Encrypt(pt1);
  Ciphertext ct2 = pub.Encrypt(pt2);

  // Perform homomorphic addition
  Ciphertext ct = ct1 + ct2;

  // Decrypt resultant ciphertext
  Plaintext pt = priv.Decrypt(ct);

  // Compute the additions in the plaintext ring 
  ZZ_pPush push;
  ZZ_p::init(params.GetPlainModulus());
  ZZ_pX m_p = conv<ZZ_pX>(pt1.GetMessage()) + conv<ZZ_pX>(pt2.GetMessage());
  ZZX m = conv<ZZX>(m_p);

  REQUIRE(pt.GetMessage() == m);
}

