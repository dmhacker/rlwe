#include "rlwe.hpp"

#include <random>
#include <NTL/ZZ_pX.h>
#include <NTL/GF2X.h>

using namespace rlwe;

const float STANDARD_DEVIATION = 3.192f;

ZZX random::UniformSample(long degree, ZZ maximum) {
  ZZX poly;
  if (maximum == 2) {
    // If the maximum is 2, we can use the GF2X class 
    poly = conv<ZZX>(random_GF2X(degree));
  }
  else {
    // Otherwise, we set a temporary modulus and use the ZZ_pX class
    ZZ_pPush push;
    ZZ_p::init(maximum);
    poly = conv<ZZX>(random_ZZ_pX(degree));
  }

  return poly;
}

ZZX random::UniformSample(long degree, ZZ minimum, ZZ maximum) {
  ZZ range = maximum - minimum;
  ZZX poly = random::UniformSample(degree, range);

  // Iterate through each coefficient and add the minimum 
  for (long i = 0; i < degree; i++) {
    SetCoeff(poly, i, minimum + coeff(poly, i));
  }

  return poly;
}

// TODO: Replace with a high-quality discrete number generator (e.g. rejection sampler, Knuth-Yao algorithm)
ZZX random::GaussianSample(long degree) {
  std::random_device device;
  std::mt19937 spigot(device());
  std::normal_distribution<float> distribution(0.0f, STANDARD_DEVIATION);

  ZZX poly;
  for (long i = 0; i < degree; i++) {
    SetCoeff(poly, i, std::round(distribution(spigot))); 
  }

  return poly;
}
