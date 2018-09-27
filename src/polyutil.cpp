#include "polyutil.h"

void rlwe::RoundPoly(ZZX & result, const ZZX & poly, const ZZ & scalar, const ZZ & divisor, const ZZ & mod) {
  ZZ div2 = divisor / 2;
  for (long i = 0; i <= deg(poly); i++) {
    // See https://stackoverflow.com/questions/2422712/rounding-integer-division-instead-of-truncating 
    ZZ z = (coeff(poly, i) * scalar + div2) / divisor;
    SetCoeff(result, i, z % mod); 
  }
}

void rlwe::CenterPoly(ZZX & result, const ZZX & poly, const ZZ & mod) {
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

void rlwe::RightShiftPoly(ZZX & result, const ZZX & poly, unsigned long bits) {
  for (long i = 0; i <= deg(poly); i++) {
    // Apply a right shift to each coefficient
    SetCoeff(result, i, coeff(poly, i) >> bits);    
  }
}

void rlwe::AndPoly(ZZX & result, const ZZX & poly, const ZZ & bitmask) {
  for (long i = 0; i <= deg(poly); i++) {
    // Apply the AND bitmask to each coefficient
    SetCoeff(result, i, coeff(poly, i) & bitmask);    
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
