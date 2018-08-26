#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <NTL/matrix.h>
#include <NTL/GF2.h>

using namespace NTL;

namespace rlwe {
  // Uniformly samples a polynomial of the given length, where the coefficients lie in [min, max)
  ZZX UniformSample(long len, ZZ minimum_inclusive, ZZ maximum_exclusive);
  // Uniformly samples a polynomial of the given length, where the coefficients lie in [0, max)
  ZZX UniformSample(long len, ZZ maximum_exclusive);
  // Samples a polynomial of the given length, where each coefficient is taken from a binary probability matrix 
  ZZX KnuthYaoSample(long len, Mat<GF2> probability_matrix); 
}
