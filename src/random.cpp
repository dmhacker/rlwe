#include "rlwe.hpp"

#include <random>
#include <NTL/ZZ_pX.h>
#include <NTL/GF2X.h>

using namespace rlwe;

ZZX random::UniformSample(long degree, ZZ field_modulus, bool flip_bits) {
  ZZX poly;
  if (field_modulus == 2) {
    // If the finite field is modulo 2, we can use the GF2X class 
    poly = conv<ZZX>(random_GF2X(degree));
  }
  else {
    // Otherwise, we set a temporary modulus and use the ZZ_pX class
    ZZ_pPush push;
    ZZ_p::init(field_modulus);
    poly = conv<ZZX>(random_ZZ_pX(degree));
  }

  // Iterate through each coefficient
  if (flip_bits) {
    for (long i = 0; i < degree; i++) {
      // 50% random chance that the coefficient will be negative
      if (rand() & 1) {
        SetCoeff(poly, i, -coeff(poly, i));
      }
    }
  }

  return poly;
}

// TODO: Replace with a high-quality discrete number generator (e.g. rejection sampler, Knuth-Yao algorithm)
ZZX random::GaussianSample(long degree, float standard_deviation) {
  std::random_device device;
  std::mt19937 spigot(device());
  std::normal_distribution<float> distribution(0.0f, standard_deviation);

  ZZX poly;
  for (long i = 0; i < degree; i++) {
    SetCoeff(poly, i, std::round(distribution(spigot)));
  }

  return poly;
}
