#pragma once

#include <3rdparty/rathena/cbasetypes.hpp> //Included so data types is easier to match

#define DEFINE_PACKET_HEADER( name, id ) constexpr int16 HEADER_##name = id

#pragma pack( push, 1 )

struct PACKET_CA_LOGIN{
	int16 packetType;
	uint32 version;
	char username[24];
	char password[24];
	uint8 clienttype;
};
DEFINE_PACKET_HEADER( CA_LOGIN, 0x0064 );

struct PACKET_CA_LOGIN_HASHED{
	int16 packetType;
	char username[24];
	char passwordHash[65];
};
DEFINE_PACKET_HEADER( CA_LOGIN_HASHED, 0x0c50 );

#pragma pack( pop )

static_assert( sizeof( PACKET_CA_LOGIN ) == 55, "CA_LOGIN must be 55 bytes" );
static_assert( sizeof( PACKET_CA_LOGIN_HASHED ) == 91, "CA_LOGIN_HASHED must be 91 bytes" );
