#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <NTL/RR.h>

using namespace NTL;

namespace rlwe {
  // Scales each coefficient in the polynomial by a floating point number and then rounds the result
  void RoundCoeffs(ZZX & poly, const RR scalar, const ZZ mod);

  // Special form of rounding, defined in the Ring-TESLA paper
  void RoundCoeffsTESLA(ZZX & c, const ZZ mod_2d);

  // Centers coefficients in a polynomial so that they appear in ((-q - 1)/ 2, (q - 1)/2] instead of [0 ... q)
  void CenterCoeffs(ZZX & poly, const ZZ mod);

  // Checks to see if all coefficients are in the range [lower, upper]
  bool IsInRange(ZZX & poly, const ZZ lower, const ZZ upper);
}
