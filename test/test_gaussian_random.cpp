#include "catch.hpp"
#include "../src/rlwe.hpp"

TEST_CASE("Gaussian sampling over generic standard deviation") {
  int DEGREE = 100;
  NTL::ZZX poly = rlwe::random::GaussianSample(DEGREE);
  REQUIRE(NTL::deg(poly) < DEGREE);
}
