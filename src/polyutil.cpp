#include "polyutil.h"

void rlwe::RoundCoeffs(ZZX & poly, const RR scalar, const ZZ mod) {
  for (long i = 0; i <= deg(poly); i++) {
    // Convert each coefficient into their floating point equivalent before rounding 
    RR r = conv<RR>(coeff(poly, i));
    r *= scalar;
    round(r, r);

    // Convert coefficient back to integer equivalent and perform modulo operation
    SetCoeff(poly, i, conv<ZZ>(r) % mod); 
  }
}

void rlwe::RoundCoeffsTESLA(ZZX & c, const ZZ mod_2d) {
  // Perform [c]_{2^d}
  ZZX c_2d(c); 
  rlwe::CenterCoeffs(c_2d, mod_2d); 

  // Compute result = (c - [c]_{2^d}) / 2^d
  c -= c_2d;
  c /= mod_2d;
}

void rlwe::CenterCoeffs(ZZX & poly, const ZZ mod) {
  ZZ center_point = mod / 2;
  for (long i = 0; i <= deg(poly); i++) {
    // Apply modulus operation before centering
    ZZ coefficient = coeff(poly, i) % mod;

    // Convert any coefficients greater than the center point to their negative equivalent
    if (coefficient > center_point) {
      coefficient -= mod;
    }

    // Update the coefficient in the polynomial
    SetCoeff(poly, i, coefficient);
  }
}

bool rlwe::IsInRange(const ZZX & poly, const ZZ lower, const ZZ upper) {
  for (long i = 0; i <= deg(poly); i++) {
    // Assert that each coefficient is within [lower, upper]
    ZZ coefficient = coeff(poly, i);

    // A boundary violation means that we break early
    if (coefficient < lower || coefficient > upper) {
      return 0;
    }
  }

  // All coefficients passed their respective checks 
  return 1;
}
