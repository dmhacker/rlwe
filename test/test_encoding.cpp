#include "catch.hpp"
#include "../src/rlwe.hpp"

#include <random>

TEST_CASE("Encoding & decoding positive integer") {
  // Set up parameters
  rlwe::KeyParameters params(16, ZZ(874), ZZ(7));  

  NTL:ZZ plaintext(1337);

  rlwe::Plaintext encoded = params.EncodeInteger(plaintext);
  NTL::ZZ decoded = params.DecodeInteger(encoded);

  // Make sure the decrypted plaintext equals the original 
  REQUIRE(plaintext == decoded);
}

TEST_CASE("Encoding & decoding negative integer") {
  // Set up parameters
  rlwe::KeyParameters params(16, ZZ(874), ZZ(7));  

  NTL:ZZ plaintext(-1337);

  rlwe::Plaintext encoded = params.EncodeInteger(plaintext);
  NTL::ZZ decoded = params.DecodeInteger(encoded);

  // Make sure the decrypted plaintext equals the original 
  REQUIRE(plaintext == decoded);
}

TEST_CASE("Encryption & decryption with encoding") {
  // Set up parameters
  rlwe::KeyParameters params(16, ZZ(874), ZZ(7));  

  // Compute keys
  rlwe::PrivateKey priv = params.GeneratePrivateKey();
  rlwe::PublicKey pub = params.GeneratePublicKey(priv);

  // Generate random plaintext
  NTL::ZZ integer = NTL::RandomBits_ZZ(params.GetPolyModulusDegree());
  if (NTL::RandomBits_long(1)) {
    integer *= -1;
  }

  // Convert plaintext -> encoding -> ciphertext -> decrypted -> decoding 
  rlwe::Plaintext encoded = params.EncodeInteger(integer);
  rlwe::Ciphertext ciphertext = pub.Encrypt(encoded);
  rlwe::Plaintext decrypted = priv.Decrypt(ciphertext);
  NTL:ZZ decoded = params.DecodeInteger(decrypted);

  // Make sure the decrypted plaintext equals the original 
  REQUIRE(integer == decoded);
}
