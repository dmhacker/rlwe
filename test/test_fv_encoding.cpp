#include "catch.hpp"
#include "../src/fv.hpp"

#include <random>

using namespace rlwe::fv;

TEST_CASE("Encoding & decoding positive integer") {
  // Set up parameters
  KeyParameters params(16, 874, 7);  

  NTL:ZZ plaintext(1337);

  Plaintext encoded(plaintext, params); 
  NTL::ZZ decoded = encoded.ToInteger(); 

  // Make sure the decrypted plaintext equals the original 
  REQUIRE(plaintext == decoded);
}

TEST_CASE("Encoding & decoding negative integer") {
  // Set up parameters
  KeyParameters params(16, 874, 7);  

  NTL:ZZ plaintext(-1337);

  Plaintext encoded(plaintext, params); 
  NTL::ZZ decoded = encoded.ToInteger(); 

  // Make sure the decrypted plaintext equals the original 
  REQUIRE(plaintext == decoded);
}

TEST_CASE("Encryption & decryption with encoding") {
  // Set up parameters
  KeyParameters params(16, 874, 7);  

  // Compute keys
  PrivateKey priv(params);
  PublicKey pub(priv);

  // Generate random plaintext
  NTL::ZZ integer = NTL::RandomBits_ZZ(params.GetPolyModulusDegree());
  if (NTL::RandomBits_long(1)) {
    integer *= -1;
  }

  // Convert plaintext -> encoding -> ciphertext -> decrypted -> decoding 
  Plaintext encoded(integer, params); 
  Ciphertext ciphertext = pub.Encrypt(encoded);
  Plaintext decrypted = priv.Decrypt(ciphertext);
  NTL:ZZ decoded = decrypted.ToInteger();

  // Make sure the decrypted plaintext equals the original 
  REQUIRE(integer == decoded);
}
