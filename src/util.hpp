#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <NTL/RR.h>

using namespace NTL;

namespace rlwe {
  // Scales each coefficient in the polynomial by a floating point number and then rounds the result
  void ScaleCoeffs(ZZX & poly, const RR scalar, const ZZ mod);
  // Centers coefficients in a polynomial so that they appear from {(-q - 1)/ 2 ... (q - 1)/2} instead of {0 ... q}
  void CenterCoeffs(ZZX & poly, const ZZ mod);
}
