#include <NTL/ZZX.h>
#include <NTL/ZZ.h>
#include <NTL/pair.h>
#include <sodium.h>

#define DEFAULT_POLY_MODULUS_DEGREE 512
#define DEFAULT_ERROR_STANDARD_DEVIATION 52.0f 
#define DEFAULT_ERROR_BOUND 2766
#define DEFAULT_ENCODING_WEIGHT 19
#define DEFAULT_SIGNATURE_BOUND 4194303
#define DEFAULT_SIGNATURE_BOUND_ADJUSTMENT 3173
#define DEFAULT_LEAST_SIGNIFICANT_BITS 23
#define DEFAULT_COEFF_MODULUS 39960577LL

using namespace NTL;

namespace rlwe {
  namespace tesla {
    class KeyParameters;
    class SigningKey;
    class VerificationKey;
    class Signature;

    /* Key generation */
    void GenerateSigningKey(SigningKey & signer);
    void GenerateVerificationKey(VerificationKey & verif, const SigningKey & signer);

    /* Object-oriented variants */
    SigningKey GenerateSigningKey(const KeyParameters & params);
    VerificationKey GenerateVerificationKey(const SigningKey & signer);

    /* Signing & verifying */
    void Sign(Signature & sig, const std::string & message, const SigningKey & signer); 
    bool Verify(const std::string & message, const Signature & sig, const VerificationKey & verif);

    /* Object-oriented variants */
    Signature Sign(const std::string & message, const SigningKey & signer);

    /* Util functions */
    void Hash(unsigned char * output, const ZZX & p1, const ZZX & p2, 
        const std::string & message, const KeyParameters & params);
    void Encode(ZZX & dest, const unsigned char * hash_val, const KeyParameters & params); 

    class KeyParameters {
      private:
        /* Given parameters */ 
        size_t n;
        float sigma;
        ZZ L;
        uint32_t w;
        ZZ B;
        ZZ U;
        uint32_t d;
        ZZ q;
        Pair<ZZX, ZZX> a;
        /* Calculated */
        ZZ pow_2d;
        ZZ_pXModulus phi;
        uint8_t ** pmat;
        size_t pmat_rows;
      public:
        /* Constructors */
        KeyParameters(); 
        KeyParameters(const ZZX & a1, const ZZX & a2);
        KeyParameters(const ZZX & a1, const ZZX & a2, 
            size_t n, float sigma, const ZZ & L, uint32_t w, 
            const ZZ & B, const ZZ & U, uint32_t d, const ZZ & q); 

        /* Destructors */
        ~KeyParameters() {
          for (size_t i = 0; i < pmat_rows; i++) {
            free(pmat[i]);
          }
          free(pmat);
        }

        /* Getters */
        const Pair<ZZX, ZZX> & GetPolyConstants() const { return a; }
        const ZZ_pXModulus & GetPolyModulus() const { return phi; }
        size_t GetPolyModulusDegree() const { return n; }
        float GetErrorStandardDeviation() const { return sigma; }
        const ZZ & GetErrorBound() const { return L; }
        uint32_t GetEncodingWeight() const { return w; }
        const ZZ & GetSignatureBound() const { return B; } 
        const ZZ & GetSignatureBoundAdjustment() const { return U; }
        uint32_t GetLSBCount() const { return d; }
        const ZZ & GetLSBValue() const { return pow_2d; }
        const ZZ & GetCoeffModulus() const { return q; }
        uint8_t ** GetProbabilityMatrix() const { return pmat; }
        size_t GetProbabilityMatrixRows() const { return pmat_rows; }

        /* Equality */
        bool operator== (const KeyParameters & kp) const {
          return n == kp.n && sigma == kp.sigma && L == kp.L && w == kp.w && 
            B == kp.B && U == kp.U && d == kp.d && q == kp.q && a == kp.a;
        }

        /* Display to output stream */
        friend std::ostream & operator<< (std::ostream & stream, const KeyParameters & params) {
          return stream << 
            "{n = " << params.n << 
            ", sigma = " << params.sigma << 
            ", q = " << params.q << 
            ", a = " << params.a <<
            "}";
        }
    };

    class SigningKey {
      private:
        ZZX s;
        Pair<ZZX, ZZX> e;
        const KeyParameters & params;
      public:
        /* Constructors */
        SigningKey(const KeyParameters & params) : params(params) {}

        /* Getters */
        const ZZX & GetSecret() const {
          return s;
        }
        const Pair<ZZX, ZZX> GetErrors() const {
          return e;
        }
        const KeyParameters & GetParameters() const {
          return params;
        }

        /* Setters */
        void SetSecret(const ZZX & secret) {
          this->s = secret;
        }
        void SetErrors(const ZZX & e1, const ZZX & e2) {
          this->e.a = e1;
          this->e.b = e2;
        }

        /* Display to output stream */
        friend std::ostream & operator<< (std::ostream & stream, const SigningKey & signer) {
          return stream << "{s = " << signer.s << ", e = " << signer.e << "}";
        }
    };

    class VerificationKey {
      private:
        Pair<ZZX, ZZX> t;
        const KeyParameters & params;
      public:
        /* Constructors */
        VerificationKey(const KeyParameters & params) : params(params) {}

        /* Getters */
        const Pair<ZZX, ZZX> & GetValues() const {
          return t;
        }
        const KeyParameters & GetParameters() const {
          return params;
        }

        /* Setters */
        void SetValues(const ZZX & t1, const ZZX & t2) {
          this->t.a = t1;
          this->t.b = t2;
        }

        /* Display to output stream */
        friend std::ostream & operator<< (std::ostream & stream, const VerificationKey & verif) {
          return stream << verif.t;
        }
    };

    class Signature {
      private:
        ZZX z;
        unsigned char * c_prime;
        const KeyParameters & params;
      public:
        /* Constructors */
        Signature(const KeyParameters & params) : params(params) {
          c_prime = (unsigned char *) malloc(crypto_hash_sha256_BYTES);
        }

        /* Destructors */
        ~Signature() {
          delete c_prime;
        }

        /* Getters */
        const ZZX & GetValue() const {
          return z;
        }
        const unsigned char * GetHash() const {
          return c_prime;
        }
        const KeyParameters & GetParameters() const {
          return params;
        }

        /* Setters */
        void SetValue(const ZZX & value) {
          this->z = value;
        }
        void SetHash(const unsigned char * c_prime) {
          memcpy(this->c_prime, c_prime, crypto_hash_sha256_BYTES);
        }

        /* Display to output stream */
        friend std::ostream & operator<< (std::ostream & stream, const Signature & sig) {
          return stream << "{z = " << sig.z << ", c' = " << sig.c_prime << "}";
        }
    };
  }
}
