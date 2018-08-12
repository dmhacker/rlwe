#include "catch.hpp"
#include "../src/rlwe.hpp"

TEST_CASE("Gaussian sampling over generic standard deviation") {
  const int DEGREE = 100;
  const float STANDARD_DEVIATION = 3.192;

  NTL::ZZX poly = rlwe::random::GaussianSample(DEGREE, STANDARD_DEVIATION);

  REQUIRE(NTL::deg(poly) == DEGREE - 1);
}
