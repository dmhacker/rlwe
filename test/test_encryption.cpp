#include "catch.hpp"
#include "../src/rlwe.hpp"

TEST_CASE("Encryption & decryption using small parameters") {
  // Set up parameters
  rlwe::KeyParameters params(16, ZZ(874), ZZ(7));  

  // Compute keys
  rlwe::PrivateKey priv = params.GeneratePrivateKey();
  rlwe::PublicKey pub = params.GeneratePublicKey(priv);

  // Generate random plaintext
  NTL::ZZX plaintext = rlwe::random::UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus(), false);

  // Convert to ciphertext and then back to plaintext
  rlwe::Ciphertext ciphertext = pub.Encrypt(plaintext);
  NTL::ZZX decrypted = priv.Decrypt(ciphertext);

  // Make sure the decrypted plaintext equals the original 
  REQUIRE(plaintext == decrypted);
}

/* TEST_CASE("Encryption & decryption using large parameters") { */
/*   // Set up parameters */
/*   rlwe::KeyParameters params(4096, ZZ(9214347247561474048), ZZ(290764801)); */  

/*   // Compute keys */
/*   rlwe::PrivateKey priv = params.GeneratePrivateKey(); */
/*   rlwe::PublicKey pub = params.GeneratePublicKey(priv); */

/*   // Generate random plaintext */
/*   NTL::ZZX plaintext = rlwe::random::UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus(), false); */

/*   // Convert to ciphertext and then back to plaintext */
/*   rlwe::Ciphertext ciphertext = pub.Encrypt(plaintext); */
/*   NTL::ZZX decrypted = priv.Decrypt(ciphertext); */

/*   // Make sure the decrypted plaintext equals the original */ 
/*   REQUIRE(plaintext == decrypted); */
/* } */

