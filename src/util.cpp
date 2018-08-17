#include "rlwe.hpp"

using namespace rlwe;

// Scales each coefficient in the polynomial by a floating point number and then rounds the result
void util::ScaleCoeffs(ZZX & poly, const RR scalar, const ZZ mod) {
  for (long i = 0; i <= deg(poly); i++) {
    RR rounded_coefficient = round(conv<RR>(coeff(poly, i)) * scalar); 
    SetCoeff(poly, i, conv<ZZ>(rounded_coefficient) % mod);
  }
}

// Centers coefficients in a polynomial so that they appear from {(-q - 1)/ 2 ... (q - 1)/2} instead of {0 ... q}
void util::CenterCoeffs(ZZX & poly, const ZZ mod) {
  ZZ center_point = mod / 2;
  for (long i = 0; i <= deg(poly); i++) {
    ZZ coefficient = coeff(poly, i);
    if (coefficient > center_point) {
      SetCoeff(poly, i, coefficient - mod);
    }
  }
}
