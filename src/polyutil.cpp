#include "polyutil.h"
#include <cassert>

void rlwe::RoundCoeffs(ZZX & result, const ZZX & poly, const RR & scalar, const ZZ & mod) {
  for (long i = 0; i <= deg(poly); i++) {
    // Convert each coefficient into their floating point equivalent before rounding 
    RR r = conv<RR>(coeff(poly, i));
    r *= scalar;
    round(r, r);

    // Convert coefficient back to integer equivalent and perform modulo operation
    SetCoeff(result, i, conv<ZZ>(r) % mod); 
  }
}

void rlwe::CenterCoeffs(ZZX & result, const ZZX & poly, const ZZ & mod) {
  ZZ center_point = mod / 2;
  for (long i = 0; i <= deg(poly); i++) {
    // Apply modulus operation before centering
    ZZ coefficient = coeff(poly, i) % mod;

    // Convert any coefficients greater than the center point to their negative equivalent
    if (coefficient > center_point) {
      coefficient -= mod;
    }

    // Update the coefficient in the polynomial
    SetCoeff(result, i, coefficient);
  }
}

void rlwe::RightShiftCoeffs(ZZX & result, const ZZX & poly, long bits) {
  for (long i = 0; i <= deg(poly); i++) {
    SetCoeff(result, i, coeff(poly, i) >> bits);    
  }
}

void rlwe::AndCoeffs(ZZX & result, const ZZX & poly, const ZZ & mask) {
  for (long i = 0; i <= deg(poly); i++) {
    SetCoeff(result, i, coeff(poly, i) & mask);    
  }
}

bool rlwe::IsInRange(const ZZX & poly, const ZZ & lower, const ZZ & upper) {
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
