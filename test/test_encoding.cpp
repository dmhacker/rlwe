#include "catch.hpp"
#include "../src/rlwe.hpp"

#include <random>

TEST_CASE("Encoding & decoding positive integer") {
  // Set up parameters
  rlwe::KeyParameters params(16, ZZ(874), ZZ(7));  

  NTL:ZZ plaintext(1337);

  NTL::ZZX encoded = params.EncodeInteger(plaintext);
  NTL::ZZ decoded = params.DecodeInteger(encoded);

  // Make sure the decrypted plaintext equals the original 
  REQUIRE(plaintext == decoded);
}

TEST_CASE("Encoding & decoding negative integer") {
  // Set up parameters
  rlwe::KeyParameters params(16, ZZ(874), ZZ(7));  

  NTL:ZZ plaintext(-1337);

  NTL::ZZX encoded = params.EncodeInteger(plaintext);
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
  NTL::ZZ plaintext = NTL::RandomBits_ZZ(params.GetPolyModulusDegree());
  if (NTL::RandomBits_long(1)) {
    plaintext *= -1;
  }

  // Convert plaintext -> encoding -> ciphertext -> decrypted -> decoding 
  NTL::ZZX encoding = params.EncodeInteger(plaintext);
  rlwe::Ciphertext ciphertext = pub.Encrypt(encoding);
  NTL::ZZX decrypted = priv.Decrypt(ciphertext);
  NTL:ZZ decoding = params.DecodeInteger(decrypted);

  // Make sure the decrypted plaintext equals the original 
  REQUIRE(plaintext == decoding);
}
