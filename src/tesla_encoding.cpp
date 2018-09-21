#include "tesla.h"
#include "sha256.h"

#include <sstream>

using namespace rlwe;
using namespace rlwe::tesla;

std::string tesla::Hash(const ZZX & p1, const ZZX & p2, const std::string & message) {
  // Concatenate everything into a single string
  std::stringstream ss;
  ss << p1 << p2 << message;

  // Convert stream into actual string
  std::string result;
  ss >> result;

  // Return SHA-256 of concatenated string
  return sha256(result);
}

ZZX tesla::Encode(const std::string & hash_val) {
  // TODO: Implement encoding algorithm described in the paper    
}
