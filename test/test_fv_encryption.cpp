#include "catch.hpp"
#include "../src/fv.hpp"
#include "../src/sampling.hpp"

using namespace rlwe;
using namespace rlwe::fv;

TEST_CASE("Encryption & decryption using small parameters") {
  // Set up parameters
  KeyParameters params(16, 874, 7);  

  // Compute keys
  PrivateKey priv = GeneratePrivateKey(params);
  PublicKey pub = GeneratePublicKey(priv);

  // Generate random plaintext
  Plaintext plaintext(UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()), params);

  // Convert to ciphertext and then back to plaintext
  Ciphertext ciphertext = Encrypt(plaintext, pub);
  Plaintext decrypted = Decrypt(ciphertext, priv);

  // Make sure the decrypted plaintext equals the original 
  REQUIRE(plaintext == decrypted);
}

TEST_CASE("Encryption & decryption using large parameters") {
  // Set up parameters
  KeyParameters params(4096, 9214347247561474048, 290764801);  

  // Compute keys
  PrivateKey priv = GeneratePrivateKey(params);
  PublicKey pub = GeneratePublicKey(priv);

  // Generate random plaintext
  Plaintext plaintext(UniformSample(params.GetPolyModulusDegree(), params.GetPlainModulus()), params);

  // Convert to ciphertext and then back to plaintext
  Ciphertext ciphertext = Encrypt(plaintext, pub);
  Plaintext decrypted = Decrypt(ciphertext, priv);

  // Make sure the decrypted plaintext equals the original 
  REQUIRE(plaintext == decrypted);
}
