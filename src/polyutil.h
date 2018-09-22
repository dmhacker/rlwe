#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <NTL/RR.h>

using namespace NTL;

namespace rlwe {
  // Scales each coefficient in the polynomial by a floating point number and then rounds the result
  void RoundCoeffs(ZZX & result, const ZZX & poly, const RR & scalar, const ZZ & mod);

  // Centers coefficients in a polynomial so that they appear in ((-q - 1)/ 2, (q - 1)/2] instead of [0 ... q)
  void CenterCoeffs(ZZX & result, const ZZX & poly, const ZZ & mod);

  // Applies a right shift to each coefficient by `bits` number of bits 
  void RightShiftCoeffs(ZZX & result, const ZZX & poly, long bits);

  // Applies an AND mask to each coefficient
  void AndCoeffs(ZZX & result, const ZZX & poly, const ZZ & mask);

  // Checks to see if all coefficients are in the range [lower, upper]
  bool IsInRange(const ZZX & poly, const ZZ & lower, const ZZ & upper);
}
