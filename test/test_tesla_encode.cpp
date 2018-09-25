#include "catch.hpp"
#include "tesla.h"
#include "sample.h"

using namespace rlwe;
using namespace rlwe::tesla;

TEST_CASE("Encoding a hash value into a polynomial") {
  KeyParameters params;

  // Generate some random values 
  unsigned char hsh[crypto_hash_sha256_BYTES];
  NTL::ZZX p1 = UniformSample(params.GetPolyModulusDegree(), params.GetCoeffModulus()); 
  NTL::ZZX p2 = UniformSample(params.GetPolyModulusDegree(), params.GetCoeffModulus()); 
  std::string message = "woweee!";
  
  // Produce a hash and initial encoding 
  ZZX output;
  Hash(hsh, p1, p2, message, params);
  Encode(output, hsh, params);

  // Count the number of non-zero coefficients
  int w = 0;
  for (int i = 0; i <= NTL::deg(output); i++) {
    NTL::ZZ c = NTL::coeff(output, i);
    if (c == 1 || c == -1) {
      w += 1;
    }
  }

  // Assert that the number of 1's and -1's in the encoding is equal to the encoding weight 
  REQUIRE(w == params.GetEncodingWeight());

  // Assert that the output has a degree less than the given polynomial modulus
  REQUIRE(NTL::deg(output) < params.GetPolyModulusDegree());

  // Assert that the output is deterministic and can be replicated
  ZZX replicated;
  Encode(replicated, hsh, params);
  REQUIRE(output == replicated);
}
