#include "sampling.hpp"

#include <NTL/ZZX.h>
#include <NTL/ZZ.h>
#include <NTL/pair.h>
#include <NTL/GF2.h>
#include <NTL/matrix.h>
#include <NTL/vec_vec_GF2.h>

using namespace NTL;

namespace rlwe {
  namespace tesla {
    class KeyParameters;
    class SigningKey;
    class VerificationKey;

    /* Procedural key generation */
    SigningKey GenerateSigningKey(const KeyParameters & params);
    VerificationKey GenerateVerificationKey(const SigningKey & sign);

    class KeyParameters {
      private:
        /* Given parameters */ 
        long n;
        float sigma;
        long L;
        ZZ w;
        ZZ B;
        ZZ U;
        ZZ d;
        ZZ q;
        Pair<ZZX, ZZX> a;
        /* Calculated */
        ZZ_pXModulus phi;
        Mat<GF2> probability_matrix;
      public:
        /* Constructors */
        KeyParameters() : // 128-bit security, parameters recommended by the original paper
          KeyParameters(512, 52.0f, 2766, ZZ(19), ZZ(4194303), ZZ(3173), ZZ(23), conv<ZZ>("39960577")) {}
        KeyParameters(long n, float sigma, long L, ZZ w, ZZ B, ZZ U, ZZ d, ZZ q);
        KeyParameters(long n, float sigma, long L, ZZ w, ZZ B, ZZ U, ZZ d, ZZ q, ZZX a1, ZZX a2);

        /* Getters */
        long GetPolyModulusDegree() const { return n; }
        float GetErrorStandardDeviation() const { return sigma; }
        long GetErrorBound() const { return L; }
        const ZZ & GetCoeffModulus() const { return q; }
        const ZZ & GetLSBCheckCount() const { return d; }
        const ZZ & GetEncodingWeight() const { return w; }
        const ZZ & GetB() const { return B; } /* TODO: Fix names for these two getters */
        const ZZ & GetU() const { return U; }
        const Pair<ZZX, ZZX> & GetPolyConstants() const { return a; }
        const ZZ_pXModulus & GetPolyModulus() const { return phi; }
        const Mat<GF2> & GetProbabilityMatrix() const { return probability_matrix; }

        /* Display to output stream */
        friend std::ostream& operator<< (std::ostream& stream, const KeyParameters & params) {
          return stream << "n = " << params.n << ", sigma = " << params.sigma << ", q = " << params.q;
        }

        /* Equality */
        bool operator== (const KeyParameters & kp) const {
          return n == kp.n && sigma == kp.sigma && L == kp.L && w == kp.w && 
            B == kp.B && U == kp.U && d == kp.d && q == kp.q;
        }
    };

    class SigningKey {
      private:
        ZZX s;
        Pair<ZZX, ZZX> e;
        const KeyParameters & params;
      public:
        /* Constructors */
        SigningKey(const ZZX & secret, const ZZX & e1, const ZZX & e2, const KeyParameters & params) : s(secret), e(e1, e2), params(params) {}

        /* Getters */
        const ZZX & GetSecret() const {
          return s;
        }
        const Pair<ZZX, ZZX> GetErrorValues() const {
          return e;
        }
        const KeyParameters & GetParameters() const {
          return params;
        }

        /* Display to output stream */
        friend std::ostream& operator<< (std::ostream& stream, const SigningKey & sign) {
          return stream << "[" << sign.s << ", " << sign.e << "]";
        }
    };

    class VerificationKey {
      private:
        Pair<ZZX, ZZX> t;
        const KeyParameters & params;
      public:
        /* Constructors */
        VerificationKey(const ZZX & t0, const ZZX & t1, const KeyParameters & params) : t(t0, t1), params(params) {}

        /* Getters */
        const Pair<ZZX, ZZX> & GetValues() const {
          return t;
        }
        const KeyParameters & GetParameters() const {
          return params;
        }

        /* Display to output stream */
        friend std::ostream& operator<< (std::ostream& stream, const VerificationKey & verif) {
          return stream << verif.t;
        }
    };
  }
}
