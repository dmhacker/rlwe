#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <NTL/matrix.h>
#include <NTL/GF2.h>

using namespace NTL;

#define PROBABILITY_MATRIX_BYTE_PRECISION 8
#define PROBABILITY_MATRIX_BIT_PRECISION 64

namespace rlwe {
  // Uniformly samples a polynomial of the given length, where the coefficients lie in [min, max)
  ZZX UniformSample(long len, ZZ minimum_inclusive, ZZ maximum_exclusive);
  // Uniformly samples a polynomial of the given length, where the coefficients lie in [0, max)
  ZZX UniformSample(long len, ZZ maximum_exclusive);
  // Populates a compressed binary probability matrix for use in the Knuth-Yao sampling algorithm
  void KnuthYaoGaussianMatrix(char ** pmat, size_t pmat_rows, float sigma);
  // Samples a polynomial of the given length, where each coefficient is taken from a binary probability matrix 
  ZZX KnuthYaoSample(long len, char ** pmat, size_t pmat_rows);
}
