#include "sampling.hpp"
#include "defines.hpp"

#include <random>
#include <NTL/ZZ_pX.h>
#include <NTL/GF2X.h>

ZZX rlwe::UniformSample(long len, ZZ maximum) {
  ZZX poly;
  if (maximum == 2) {
    // If the maximum is 2, we can use the GF2X class 
    poly = conv<ZZX>(random_GF2X(len));
  }
  else {
    // Otherwise, we set a temporary modulus and use the ZZ_pX class
    ZZ_pPush push;
    ZZ_p::init(maximum);
    poly = conv<ZZX>(random_ZZ_pX(len));
  }

  return poly;
}

ZZX rlwe::UniformSample(long len, ZZ minimum, ZZ maximum) {
  ZZ range = maximum - minimum;
  ZZX poly = rlwe::UniformSample(len, range);

  // Iterate through each coefficient and add the minimum 
  for (long i = 0; i < len; i++) {
    SetCoeff(poly, i, minimum + coeff(poly, i));
  }

  return poly;
}

ZZX rlwe::KnuthYaoSample(long len, const Mat<GF2> & probability_matrix) {
  ZZX poly;

  // Perform the Knuth-Yao sampling algorithm and navigate the DDG
  int last_row = probability_matrix.NumRows() - 1;
  for (long i = 0; i < len; i++) {
    // Setup: initialize random bit, counters, etc.
    GF2 r;
    int d = 0; 
    int hit = 0;
    int col = 0;

    // Keep iterating through columns until a hit, generate a random bit each time
    while (!hit) { 
      random(r);
      d = 2 * d + IsZero(r); 

      // Iterate through rows of probability matrix
      for (int row = last_row; row >= 0; row--) {
        d -= IsOne(probability_matrix[row][col]);

        // Reached terminal node in the DDG
        if (d == -1) {
          // Randomly flip chosen value and make it negative
          random(r);
          SetCoeff(poly, i, IsOne(r) ? row : -row); 

          // Register that we have found a sample value
          hit = 1;
          break;
        }
      }
      col++;
    }
  }

  return poly;
}
