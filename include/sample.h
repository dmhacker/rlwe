#include <NTL/ZZ.h>
#include <NTL/ZZX.h>

using namespace NTL;

#define PROBABILITY_MATRIX_BYTE_PRECISION 8
#define PROBABILITY_MATRIX_BIT_PRECISION 64
#define PROBABILITY_MATRIX_BOUNDS_SCALAR 6

namespace rlwe {
  // Uniformly samples a polynomial of the given length, where the coefficients lie in [min, max)
  void UniformSample(ZZX & poly, size_t len, const ZZ & minimum_inclusive, const ZZ & maximum_exclusive);
  ZZX UniformSample(size_t len, const ZZ & minimum_inclusive, const ZZ & maximum_exclusive);

  // Uniformly samples a polynomial of the given length, where the coefficients lie in [0, max)
  void UniformSample(ZZX & poly, size_t len, const ZZ & maximum_exclusive);
  ZZX UniformSample(size_t len, const ZZ & maximum_exclusive);

  // Generates a compressed binary probability matrix for use in the Knuth-Yao sampling algorithm
  void KnuthYaoGaussianMatrix(char ** pmat, size_t pmat_rows, float sigma);
  char ** KnuthYaoGaussianMatrix(size_t pmat_rows, float sigma);

  // Samples a polynomial of the given length, where each coefficient is taken from a binary probability matrix 
  void KnuthYaoSample(ZZX & poly, size_t len, char ** pmat, size_t pmat_rows);
  ZZX KnuthYaoSample(size_t len, char ** pmat, size_t pmat_rows);
}
