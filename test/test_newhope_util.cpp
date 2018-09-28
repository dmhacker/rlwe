#include "catch.hpp"
#include "sample.h"
#include "newhope.h"

#include <sodium.h>

using namespace rlwe;
using namespace rlwe::newhope;

TEST_CASE("Polynomial compression & decompression") {
  // Sample polynomial randomly
  ZZX poly = UniformSample(16, ZZ(16));

  // Compress the polynomial into 64 bytes
  uint8_t compressed[64]; 
  CompressPoly(compressed, 4, poly);
  
  // Decompress the polynomial
  ZZX decompressed;
  DecompressPoly(decompressed, 16, compressed, 4);

  // Make sure original polynomial equals the decompressed version
  REQUIRE(poly == decompressed);
}

TEST_CASE("NHSEncode & NHSDecode functions") {
  KeyParameters params;

  // Sample original seed value randomly
  uint8_t original[SHARED_KEY_BYTE_LENGTH]; 
  randombytes_buf(original, SHARED_KEY_BYTE_LENGTH); 

  // Encode the seed into a polynomial
  ZZX encoding;
  NHSEncode(encoding, original, params.GetCoeffModulus());

  // Decode the polynomial back into the seed value
  uint8_t decoding[SHARED_KEY_BYTE_LENGTH]; 
  NHSDecode(decoding, encoding, params.GetCoeffModulus());

  // Make sure the decoded and original versions are equivalent
  bool equivalent = true;
  for (size_t i = 0; i < SHARED_KEY_BYTE_LENGTH; i++) {
    if (original[i] != decoding[i]) {
      equivalent = false;
      break;
    }
  }
  REQUIRE(equivalent);
}

TEST_CASE("NHSCompress & NHSDecompress functions") {
  KeyParameters params;

  // Sample ciphertext randomly
  ZZX c = UniformSample(params.GetPolyModulusDegree(), params.GetCoeffModulus());

  // Compress the ciphertext
  ZZX compressed;
  NHSCompress(compressed, c, params.GetCoeffModulus());

  // Decompress the ciphertext
  ZZX decompressed;
  NHSDecompress(decompressed, compressed, params.GetCoeffModulus());

  // Make sure that both versions are nearly equivalent (within a certain tolerance)
  bool nearly_equivalent = true; 
  ZZ tolerance = params.GetCoeffModulus() / 8;
  ZZ upper_tolerance = params.GetCoeffModulus() - tolerance;
  for (size_t i = 0; i < params.GetPolyModulusDegree(); i++) {
    ZZ diff = abs(coeff(decompressed, i) - coeff(c, i)); 
    if (diff > tolerance && diff < upper_tolerance) {
      nearly_equivalent = false;
      break;
    }
  }
  REQUIRE(nearly_equivalent);
}
