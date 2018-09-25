#include <NTL/ZZ.h>
#include <NTL/ZZX.h>
#include <NTL/RR.h>
#include <NTL/GF2.h>
#include <NTL/pair.h>
#include <NTL/matrix.h>
#include <NTL/vec_vec_GF2.h>

#define DEFAULT_ERROR_STANDARD_DEVIATION 3.192f
#define DEFAULT_DECOMPOSITION_BIT_COUNT 32

using namespace NTL;

namespace rlwe {
  namespace fv {
    class KeyParameters;
    class PrivateKey;
    class PublicKey;
    class EvaluationKey;
    class Plaintext;
    class Ciphertext;

    /* Key generation */
    PrivateKey GeneratePrivateKey(const KeyParameters & params);
    PublicKey GeneratePublicKey(const PrivateKey & priv);
    PublicKey GeneratePublicKey(const PrivateKey & priv, const ZZX & a, const ZZX & e);
    EvaluationKey GenerateEvaluationKey(const PrivateKey & priv, long level);

    /* Procedural variants */
    void GeneratePrivateKey(PrivateKey & priv);
    void GeneratePublicKey(PublicKey & pub, const PrivateKey & priv);
    void GeneratePublicKey(PublicKey & pub, const PrivateKey & priv, const ZZX & a, const ZZX & e);
    void GenerateEvaluationKey(EvaluationKey & elk, const PrivateKey & priv, long level);

    /* Encoding & decoding (if the base is not given, it is assumed to be 2) */
    Plaintext EncodeInteger(long integer, const KeyParameters & params);
    Plaintext EncodeInteger(long integer, unsigned long base, const KeyParameters & params);
    Plaintext EncodeInteger(const ZZ & integer, const KeyParameters & params);
    Plaintext EncodeInteger(const ZZ & integer, unsigned long base, const KeyParameters & params);
    ZZ DecodeInteger(const Plaintext & ptx);
    ZZ DecodeInteger(const Plaintext & ptx, unsigned long base);

    /* Procedural variants */
    void EncodeInteger(Plaintext & ptx, long integer);
    void EncodeInteger(Plaintext & ptx, long integer, unsigned long base);
    void EncodeInteger(Plaintext & ptx, const ZZ & integer);
    void EncodeInteger(Plaintext & ptx, const ZZ & integer, unsigned long base);
    void DecodeInteger(ZZ & integer, const Plaintext & ptx);
    void DecodeInteger(ZZ & integer, const Plaintext & ptx, unsigned long base);

    /* Encryption & decryption */
    Ciphertext Encrypt(const Plaintext & ptx, const PublicKey & pub);
    Plaintext Decrypt(const Ciphertext & ctx, const PrivateKey & priv);

    /* Procedural variants */
    void Encrypt(Ciphertext & ctx, const Plaintext & ptx, const PublicKey & pub);
    void Decrypt(Plaintext & ptx, const Ciphertext & ctx, const PrivateKey & priv);

    class KeyParameters {
      private:
        /* Given parameters */ 
        long n;
        ZZ q;
        ZZ t;
        long log_w;
        float sigma;
        /* Calculated */
        ZZ_pXModulus phi;
        ZZ delta;
        RR downscale;
        ZZ w;
        ZZ w_mask;
        long l;
        char ** pmat;
        size_t pmat_rows; 
      public:
        /* Constructors */
        KeyParameters(long n, long q, long t) : KeyParameters(n, ZZ(q), ZZ(t)) {}
        KeyParameters(long n, ZZ q, ZZ t) : KeyParameters(n, q, t, DEFAULT_DECOMPOSITION_BIT_COUNT, DEFAULT_ERROR_STANDARD_DEVIATION) {}
        KeyParameters(long n, ZZ q, ZZ t, long log_w, float sigma);
        
        /* Destructors */
        ~KeyParameters() {
          for (size_t i = 0; i < pmat_rows; i++) {
            free(pmat[i]);
          }
          free(pmat);
        }

        /* Getters */
        const ZZ & GetCoeffModulus() const { return q; }
        const ZZ & GetPlainModulus() const { return t; }
        const ZZ & GetPlainToCoeffScalar() const { return delta; }
        const RR & GetCoeffToPlainScalar() const { return downscale; }
        long GetPolyModulusDegree() const { return n; }
        const ZZ_pXModulus & GetPolyModulus() const { return phi; }
        float GetErrorStandardDeviation() const { return sigma; }
        const ZZ & GetDecompositionBase() const { return w; }
        const ZZ & GetDecompositionBitMask() const { return w_mask; }
        long GetDecompositionBitCount() const { return log_w; }
        long GetDecompositionTermCount() const { return l; }
        char ** GetProbabilityMatrix() const { return pmat; }
        size_t GetProbabilityMatrixRows() const { return pmat_rows; }

        /* Display to output stream */
        friend std::ostream& operator<< (std::ostream& stream, const KeyParameters& params) {
          return stream << "[n = " << params.n << ", q = " << params.q << ", t = " << params.t << "]";
        }

        /* Equality */
        bool operator== (const KeyParameters & kp) const {
          return n == kp.n && q == kp.q && t == kp.t && log_w == kp.log_w && sigma == kp.sigma;
        }
    };

    class PrivateKey {
      private:
        ZZX s;
        const KeyParameters & params;
      public:
        /* Constructors */
        PrivateKey(const KeyParameters & params) : params(params) {}

        /* Getters */
        const ZZX & GetSecret() const { 
          return s; 
        }
        const KeyParameters & GetParameters() const { 
          return params; 
        }

        /* Setters */
        void SetSecret(const ZZX & secret) {
          this->s = secret;
        }

        /* Display to output stream */
        friend std::ostream& operator<< (std::ostream& stream, const PrivateKey& priv) {
          return stream << priv.s;
        }
    };

    class PublicKey {
      private:
        Pair<ZZX, ZZX> p;
        const KeyParameters & params;
      public:
        /* Constructors */
        PublicKey(const KeyParameters & params) : params(params) {}

        /* Getters */
        const Pair<ZZX, ZZX> & GetValues() const {
          return p;
        }
        const KeyParameters & GetParameters() const { 
          return params; 
        }

        /* Setters */
        void SetValues(const ZZX & p0, const ZZX & p1) {
          this->p.a = p0;
          this->p.b = p1;
        }

        /* Display to output stream */
        friend std::ostream& operator<< (std::ostream& stream, const PublicKey& pub) {
          return stream << pub.p;
        }
    };

    class EvaluationKey {
      private:
        Vec<Pair<ZZX, ZZX>> r;
        long level;
        const KeyParameters & params;
      public:
        /* Constructors */
        EvaluationKey(const KeyParameters & params) : params(params) {}

        /* Getters */
        const Pair<ZZX, ZZX> & operator[] (int index) const {
          return r[index]; 
        }
        long GetLength() const { 
          return r.length(); 
        }
        long GetLevel() const {
          return level;
        }
        const KeyParameters & GetParameters() const { 
          return params; 
        }

        /* Setters */
        Pair<ZZX, ZZX> & operator[] (int index) {
          return r[index]; 
        }
        void SetLevel(long level) {
          this->level = level;
        }
        void SetLength(long len) {
          this->r.SetLength(len);
        }


        /* Display to output stream */
        friend std::ostream& operator<< (std::ostream& stream, const EvaluationKey & elk) {
          return stream << elk.r; 
        }  
    };

    class Plaintext {
      private:
        ZZX m;
        const KeyParameters & params;
      public:
        /* Constructors */
        Plaintext(const KeyParameters & params) : params(params) {}

        /* Getters */
        const ZZX & GetMessage() const { 
          return m; 
        }
        const KeyParameters & GetParameters() const { 
          return params; 
        }

        /* Setters */
        void SetMessage(const ZZX & message) {
          this->m = message;
        }

        /* Equality */
        bool operator== (const Plaintext & pt) const {
          return m == pt.m && params == pt.params;
        }

        /* Display to output stream */
        friend std::ostream& operator<< (std::ostream& stream, const Plaintext& pt) {
          return stream << pt.m; 
        }
    };

    class Ciphertext {
      private:
        Vec<ZZX> c;
        const KeyParameters & params;
      public:
        /* Constructors */
        Ciphertext(const KeyParameters & params) : params(params) {}
        Ciphertext(const Ciphertext & ct) : c(ct.c), params(ct.params) {}

        /* Getters */
        const ZZX & operator[] (int index) const {
          return c[index]; 
        }
        long GetLength() const { 
          return c.length(); 
        }
        const KeyParameters & GetParameters() const { 
          return params; 
        }

        /* Setters */
        ZZX & operator[] (int index) {
          return c[index];
        }
        void SetLength(long len) {
          this->c.SetLength(len);
        }

        /* Somewhat homomorphic encryption */
        Ciphertext & Negate();
        Ciphertext & operator+= (const Ciphertext & ct);
        Ciphertext & operator*= (const Ciphertext & ct);
        Ciphertext & Relinearize(const EvaluationKey & elk);

        /* Arithmetic overloading */
        friend Ciphertext operator- (const Ciphertext & ct) {
          Ciphertext result(ct);
          result.Negate();
          return result;
        }
        friend Ciphertext operator+ (const Ciphertext & ct1, const Ciphertext & ct2) {
          Ciphertext result(ct1); 
          result += ct2;
          return result;
        }
        friend Ciphertext operator* (const Ciphertext & ct1, const Ciphertext & ct2) {
          Ciphertext result(ct1);
          result *= ct2;
          return result;
        }

        /* Equality */
        bool operator== (const Ciphertext & ct) const {
          if (c.length() != ct.c.length() || !(params == ct.params)) {
            return false;
          }

          for (int i = 0; i < c.length(); i++) {
            if (c[i] != ct.c[i]) {
              return false;
            }
          }

          return true;
        }

        /* Display to output stream */
        friend std::ostream& operator<< (std::ostream& stream, const Ciphertext& ct) {
          return stream << ct.c;
        }
    };
  }
}
