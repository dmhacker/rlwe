#include "sample.h"

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

void rlwe::KnuthYaoGaussianMatrix(char ** probability_matrix, size_t bound, float standard_deviation) {
  // Calculate some constants
  float variance = standard_deviation * standard_deviation;
  float pi2 = atan(1) * 8; 

  // Calculate probabilities and the total they sum to
  float total = 0;
  float probabilities[bound];
  for (int i = 0; i < bound; i++) {
    // Calculate probability using a Gaussian PDF 
    probabilities[i] = 1.0f / sqrt(pi2 * variance) * exp(-i * i / 2.0f / variance);

    // Positive numbers have a 50% chance to be made negative in sampling 
    // The probability of 0 must be lowered in order to compensate 
    if (i == 0) {
      probabilities[i] /= 2;
    }

    // Add it to the total
    total += probabilities[i];
  }

  float scaling_factor = 1.0f / total;
  for (int i = 0; i < bound; i++) {
    // Calculate scaled version of probability (so everything sums to 1)
    float probability = probabilities[i] * scaling_factor; 

    // Fill in the row of the matrix
    float check_value = 0.5f;
    for (int j = 0; j < PROBABILITY_MATRIX_BIT_PRECISION; j++) {
      if (probability > check_value) {
        probability_matrix[i][j / 8] |= (1 << (7 - j % 8));
        probability -= check_value;
      }
      check_value /= 2;
    }
  }
}

ZZX rlwe::KnuthYaoSample(long len, char ** probability_matrix, size_t num_rows) {
  ZZX poly;

  // Perform the Knuth-Yao sampling algorithm and navigate the DDG
  int last_row = num_rows - 1; 
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
        d -= ((probability_matrix[row][col / 8] >> (7 - col % 8)) & 1); 

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
