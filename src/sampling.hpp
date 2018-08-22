#include <NTL/ZZ.h>
#include <NTL/ZZX.h>

using namespace NTL;

namespace rlwe {
  // Uniformly samples a polynomial of the given degree, where the coefficients lie in [min, max)
  ZZX UniformSample(long degree, ZZ minimum_inclusive, ZZ maximum_exclusive);
  // Uniformly samples a polynomial of the given degree, where the coefficients lie in [0, max)
  ZZX UniformSample(long degree, ZZ maximum_exclusive);
  // Samples a polynomial of the given degree, where each coefficient is taken from a Gaussian distribution
  ZZX GaussianSample(long degree, float standard_deviation); 
}
