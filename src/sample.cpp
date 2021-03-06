#include "sample.h"

#include <NTL/GF2X.h>

void rlwe::UniformSample(ZZX & poly, size_t len, const ZZ & maximum) {
  if (maximum == 2) {
    // If the maximum is 2, we can use the GF2X class 
    GF2X tmp;
    random(tmp, len);
    conv(poly, tmp);
  }
  else {
    // Otherwise, we set a temporary modulus and use the ZZ_pX class
    ZZ_pPush push;
    ZZ_p::init(maximum);
    ZZ_pX tmp;
    random(tmp, len);
    conv(poly, tmp);
  }
}

void rlwe::UniformSample(ZZX & poly, size_t len, const ZZ & minimum, const ZZ & maximum) {
  ZZ range = maximum - minimum;
  UniformSample(poly, len, range);

  // Iterate through each coefficient and add the minimum 
  for (long i = 0; i < len; i++) {
    SetCoeff(poly, i, minimum + coeff(poly, i));
  }
}

void rlwe::KnuthYaoGaussianMatrix(uint8_t ** pmat, size_t pmat_rows, float sigma) {
  // Calculate some constants
  float variance = sigma * sigma;
  float pi2 = atan(1) * 8; 

  // Calculate probabilities and the total they sum to
  float total = 0;
  float probabilities[pmat_rows];
  for (int i = 0; i < pmat_rows; i++) {
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
  for (int i = 0; i < pmat_rows; i++) {
    // Calculate scaled version of probability (so everything sums to 1)
    float probability = probabilities[i] * scaling_factor; 

    // Fill in the row of the matrix
    float check_value = 0.5f;
    for (int j = 0; j < PROBABILITY_MATRIX_BIT_PRECISION; j++) {
      if (probability > check_value) {
        pmat[i][j / 8] |= (1 << (7 - j % 8));
        probability -= check_value;
      }
      check_value /= 2;
    }
  }
}

void rlwe::KnuthYaoSample(ZZX & poly, size_t len, uint8_t ** pmat, size_t pmat_rows) {
  // Perform the Knuth-Yao sampling algorithm and navigate the DDG
  int last_row = pmat_rows - 1; 
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
        d -= ((pmat[row][col / 8] >> (7 - col % 8)) & 1); 

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
}

ZZX rlwe::UniformSample(size_t len, const ZZ & maximum) {
  ZZX poly;
  UniformSample(poly, len, maximum);
  return poly;
}

ZZX rlwe::UniformSample(size_t len, const ZZ & minimum, const ZZ & maximum) {
  ZZX poly;
  UniformSample(poly, len, minimum, maximum);
  return poly;
}

uint8_t ** rlwe::KnuthYaoGaussianMatrix(size_t pmat_rows, float sigma) {
  uint8_t ** pmat = (uint8_t **) malloc(pmat_rows * sizeof(uint8_t *));
  for (size_t i = 0; i < pmat_rows; i++) {
    pmat[i] = (uint8_t *) calloc(PROBABILITY_MATRIX_BYTE_PRECISION, sizeof(uint8_t));
  }
  KnuthYaoGaussianMatrix(pmat, pmat_rows, sigma);
  return pmat;
}

ZZX rlwe::KnuthYaoSample(size_t len, uint8_t ** pmat, size_t pmat_rows) {
  ZZX poly;
  KnuthYaoSample(poly, len, pmat, pmat_rows);
  return poly;
}
