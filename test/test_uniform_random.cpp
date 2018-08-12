#include "../src/rlwe.hpp"
#include "catch.hpp"

#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <NTL/ZZ_p.h>

TEST_CASE("Uniform sampling over several fields") {
  const int DEGREE = 10;

  for (int m = 2; m < 100; m += 50) {
    // Generate a polynomial uniformly randomly
    NTL::ZZX poly = rlwe::random::UniformSample(DEGREE, m, false);

    // Check to make sure each coefficient is in the modulus range
    for (long i = 0; i < DEGREE; i++) {
      NTL::ZZ coeff = NTL::coeff(poly, i);
      REQUIRE(coeff >= 0);
      REQUIRE(coeff < m);
    }
  }
}

TEST_CASE("Uniform sampling with sign bit flipping") {
  const int DEGREE = 10;

  for (int m = 2; m < 100; m += 50) {
    // Generate a polynomial uniformly randomly
    NTL::ZZX poly = rlwe::random::UniformSample(DEGREE, m, true);

    // Check to make sure each coefficient is in the modulus range
    for (long i = 0; i < DEGREE; i++) {
      NTL::ZZ coeff = NTL::coeff(poly, i);
      REQUIRE(coeff > -m);
      REQUIRE(coeff < m);
    }
  }
}
