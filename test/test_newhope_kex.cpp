#include "catch.hpp"
#include "newhope.h"

using namespace rlwe;
using namespace rlwe::newhope;

TEST_CASE("NewHope-Simple full key exchange") {
  KeyParameters params;

  // Create client & server objects
  Server server = CreateServer(params);
  Client client = CreateClient(params);

  // Generate the packet from the server
  Packet clientbound_packet = CreatePacket(server);

  // Send server packet to the client
  ReadPacket(client, clientbound_packet);

  // Generate response packet from the client
  Packet serverbound_packet = CreatePacket(client);

  // Send client packet to the server
  ReadPacket(server, serverbound_packet);

  // Make sure that the shared keys are equivalent
  for (size_t i = 0; i < SHARED_KEY_BYTE_LENGTH; i++) {
    REQUIRE(client.GetSharedKey()[i] == server.GetSharedKey()[i]);
  }
}
