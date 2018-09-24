#include "catch.hpp"
#include "fv.h"
#include "polyutil.h"

using namespace rlwe::fv;

TEST_CASE("Encoding & decoding positive integer") {
  // Set up parameters
  KeyParameters params(16, 874, 7);  

  for (int base = 2; base < 4; base++) {
    // Encode and then decode a negative integer
    Plaintext ptx = EncodeInteger(1337, base, params); 
    NTL::ZZ integer = DecodeInteger(ptx, base); 

    // Make sure the decrypted plaintext equals the original 
    REQUIRE(integer == 1337);
  }
}

TEST_CASE("Encoding & decoding negative integer") {
  // Set up parameters
  KeyParameters params(16, 874, 7);  

  for (int base = 2; base < 4; base++) {
    // Encode and then decode a negative integer
    Plaintext ptx = EncodeInteger(-1337, base, params); 
    NTL::ZZ integer = DecodeInteger(ptx, base); 

    // Make sure the decrypted plaintext equals the original 
    REQUIRE(integer == -1337);
  }
}

TEST_CASE("Encoding & decoding with integer addition") {
  // Set up parameters
  KeyParameters params(16, 5767169, 29);  

  // Compute keys
  PrivateKey priv = GeneratePrivateKey(params);
  PublicKey pub = GeneratePublicKey(priv);

  // Create both an integer sum & its ciphertext equivalent
  NTL::ZZ psum;
  Ciphertext ctx = Encrypt(EncodeInteger(ZZ::zero(), params), pub);
  for (int i = 0; i < 5; i++) {
    // Get a random integer
    NTL::ZZ integer = NTL::RandomBits_ZZ(params.GetPolyModulusDegree());
    integer *= NTL::RandomBits_long(1) * 2 - 1;

    // Add it to our current sum
    psum += integer;

    // Encode it and add it to the ciphertext
    Plaintext ptx = EncodeInteger(integer, params);
    ctx += Encrypt(ptx, pub); 
  }

  // Decrypt the ciphertext to produce another integer sum
  Plaintext dptx = Decrypt(ctx, priv);
  NTL::ZZ csum = DecodeInteger(dptx); 

  // Make sure the decrypted plaintext equals the original 
  REQUIRE(psum == csum);
}
