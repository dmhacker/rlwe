#include <NTL/ZZ.h>
#include <NTL/ZZX.h>

#define DEFAULT_POLY_MODULUS_DEGREE 1024
#define DEFAULT_COEFF_MODULUS 12289
#define DEFAULT_ERROR_STANDARD_DEVIATION 2.828f

#define SEED_BYTE_LENGTH 32
#define SHARED_KEY_BYTE_LENGTH 32

using namespace NTL;

namespace rlwe {
  namespace newhope {
    class KeyParameters;
    class Server;
    class Client;

    /* Initialization procedures */
    void Initialize(Server & server);
    void Initialize(Client & client); 

    /* Packet receiving/processing */
    void ReadPacket(Client & client, const uint8_t * packet);
    void ReadPacket(Server & server, const uint8_t * packet);
    void WritePacket(uint8_t * packet, Server & server);
    void WritePacket(uint8_t * packet, Client & client);

    class KeyParameters {
      private:
        /* Given parameters */ 
        uint32_t n;
        ZZ q;
        float sigma;
        /* Calculated */
        ZZ_pXModulus phi;
        uint8_t ** pmat;
        size_t pmat_rows; 
      public:
        /* Constructors */
        KeyParameters();
        KeyParameters(uint32_t n, const ZZ & q); 
        KeyParameters(uint32_t n, const ZZ & q, float sigma);
        
        /* Destructors */
        ~KeyParameters() {
          for (size_t i = 0; i < pmat_rows; i++) {
            free(pmat[i]);
          }
          free(pmat);
        }

        /* Getters */
        const ZZ & GetCoeffModulus() const { return q; }
        long GetPolyModulusDegree() const { return n; }
        const ZZ_pXModulus & GetPolyModulus() const { return phi; }
        float GetErrorStandardDeviation() const { return sigma; }
        uint8_t ** GetProbabilityMatrix() const { return pmat; }
        size_t GetProbabilityMatrixRows() const { return pmat_rows; }

        /* Display to output stream */
        friend std::ostream& operator<< (std::ostream& stream, const KeyParameters& params) {
          return stream << "[n = " << params.n << ", q = " << params.q  << "]";
        }

        /* Equality */
        bool operator== (const KeyParameters & kp) const {
          return n == kp.n && q == kp.q && sigma == kp.sigma;
        }
    };

    class Server {
      private:
        ZZX s;
        ZZX b;
        uint8_t seed[SEED_BYTE_LENGTH];
        uint8_t shared[SHARED_KEY_BYTE_LENGTH];
        const KeyParameters & params;
      public:
        /* Getters */
        const ZZX & GetSecretKey() const {
          return s;
        }
        const ZZX & GetPublicKey() const {
          return b;
        }
        const uint8_t * GetSeed() const {
          return seed;
        }
        const uint8_t * GetSharedKey() const {
          return shared;
        }
        const KeyParameters & GetParameters() const { 
          return params; 
        }

        /* Setters */
        void SetSecretKey(const ZZX & s) {
          this->s = s;
        }
        void SetPublicKey(const ZZX & b) {
          this->b = b;
        }
        void SetSeed(const uint8_t seed[SEED_BYTE_LENGTH]) {
          memcpy(this->seed, seed, SEED_BYTE_LENGTH);
        }
        void SetSharedKey(const uint8_t shared[SHARED_KEY_BYTE_LENGTH]) {
          memcpy(this->shared, shared, SHARED_KEY_BYTE_LENGTH);
        }

        /* Display to output stream */
        friend std::ostream & operator<< (std::ostream & stream, const Server & server) {
          return stream << 
            "{s = " << server.s << 
            ", b = " << server.b << 
            ", seed = " << server.seed << 
            "}";
        }
    };

    class Client {
      private:
        ZZX s;
        ZZX u;
        ZZX c;
        uint8_t shared[SHARED_KEY_BYTE_LENGTH];
        const KeyParameters & params;
      public:
        /* Getters */
        const ZZX & GetSecretKey() const {
          return s;
        }
        const ZZX & GetPublicKey() const {
          return u;
        }
        const ZZX & GetCiphertext() const {
          return c;
        }
        const uint8_t * GetSharedKey() const {
          return shared;
        }
        const KeyParameters & GetParameters() const { 
          return params; 
        }

        /* Setters */
        void SetSecretKey(const ZZX & s) {
          this->s = s;
        }
        void SetPublicKey(const ZZX & u) {
          this->u = u;
        }
        void SetCiphertext(const ZZX & c) {
          this->c = c;
        }
        void SetSharedKey(const uint8_t shared[SHARED_KEY_BYTE_LENGTH]) {
          memcpy(this->shared, shared, SHARED_KEY_BYTE_LENGTH);
        }

        /* Display to output stream */
        friend std::ostream & operator<< (std::ostream & stream, const Client & client) {
          return stream << 
            "{s = " << client.s << 
            ", u = " << client.u << 
            ", c  = " << client.c << 
            "}";
        }
    };
  }
}
