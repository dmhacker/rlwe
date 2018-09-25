#include <NTL/ZZ.h>
#include <NTL/ZZX.h>

#define ERROR_STANDARD_DEVIATION 2.828f
#define SEED_BYTE_LENGTH 32

using namespace NTL;

namespace rlwe {
  namespace newhope {
    class KeyParameters;
    class Server;
    class Client;
    class ClientboundPacket;
    class ServerboundPacket;

    /* Initialization procedures */
    void Initialize(Server & server);
    void Initialize(Server & server, const uint8_t seed[SEED_BYTE_LENGTH]);
    void Initialize(Client & client); 

    /* Packet computation */
    void ReceivePacket(Client & client, const ClientboundPacket & packet);
    void ReceivePacket(Server & server, const ServerboundPacket & packet);

    /* Packet compression (NHSCompress, NHSDecompress are built into the functions) */ 
    void EncodeA(uint8_t * ma, const ClientboundPacket & packet);
    void DecodeA(ClientboundPacket & packet, const uint8_t * ma);
    void EncodeB(uint8_t * mb, const ServerboundPacket & packet);
    void DecodeB(ServerboundPacket & packet, const uint8_t * mb);

    class KeyParameters {
      private:
        /* Given parameters */ 
        long n;
        ZZ q;
        float sigma;
        /* Calculated */
        ZZ_pXModulus phi;
        char ** pmat;
        size_t pmat_rows; 
      public:
        /* Constructors */
        KeyParameters(long n, long q) : KeyParameters(n, ZZ(q)) {}
        KeyParameters(long n, ZZ q) : KeyParameters(n, q, ERROR_STANDARD_DEVIATION) {}
        KeyParameters(long n, ZZ q, float sigma);
        
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
        char ** GetProbabilityMatrix() const { return pmat; }
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

    class ClientboundPacket {
      private:
        ZZX b;
        uint8_t seed[SEED_BYTE_LENGTH];
        const KeyParameters & params;
      public:
        /* Constructors */
        ClientboundPacket(const KeyParameters & params) : params(params) {}

        /* Getters */
        const ZZX & GetPublicKey() const {
          return b;
        }
        const uint8_t * GetSeed() const {
          return seed;
        }
        const KeyParameters & GetParameters() const { 
          return params; 
        }

        /* Setters */
        void SetPublicKey(const ZZX & b) {
          this->b = b;
        }
        void SetSeed(const uint8_t seed[SEED_BYTE_LENGTH]) {
          memcpy(this->seed, seed, SEED_BYTE_LENGTH);
        }

        /* Equality */
        bool operator== (const ClientboundPacket & packet) const {
          for (size_t i = 0; i < SEED_BYTE_LENGTH; i++) {
            if (seed[i] != packet.seed[i]) {
              return false;
            }
          }

          return b == packet.b && params == packet.params;
        }

        /* Display to output stream */
        friend std::ostream & operator<< (std::ostream & stream, const ClientboundPacket & packet) {
          return stream << "[seed = " << packet.seed << ", b = " << packet.b << "]";
        }
    };

    class ServerboundPacket {
      private:
        ZZX u;
        ZZX c;
        const KeyParameters & params;
      public:
        /* Constructors */
        ServerboundPacket(const KeyParameters & params) : params(params) {}

        /* Getters */
        const ZZX & GetPublicKey() const {
          return u;
        }
        const ZZX & GetCiphertext() const {
          return c;
        }
        const KeyParameters & GetParameters() const { 
          return params; 
        }

        /* Setters */
        void SetPublicKey(const ZZX & u) {
          this->u = u;
        }
        void SetCiphertext(const ZZX & c) {
          this->c = c;
        }

        /* Equality */
        bool operator== (const ServerboundPacket & packet) const {
          return u == packet.u && c == packet.c && params == packet.params;
        }

        /* Display to output stream */
        friend std::ostream & operator<< (std::ostream & stream, const ServerboundPacket & packet) {
          return stream << "[u = " << packet.u << ", c  = " << packet.c << "]";
        }
    };
  }
}
