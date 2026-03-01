#include "handler.hpp"
#include "packets.hpp"

#include <sodium.h>
#include <cstring>

int handle_login( SOCKET s, const char *buf, int len, int flags, SEND_FN real_send ){
	if ( len != sizeof( PACKET_CA_LOGIN ) )
		return -1;

	const auto *login = reinterpret_cast<const PACKET_CA_LOGIN*>( buf );

	size_t pass_len = strnlen( login->password, sizeof( login->password ) );
	size_t user_len = strnlen( login->username, sizeof( login->username ) );

	unsigned char hash[crypto_generichash_BYTES];

	// BLAKE2b-256: hash the password with username as the key
	crypto_generichash(
		hash,
		sizeof( hash ),
		reinterpret_cast<const unsigned char*>( login->password ), pass_len,
		reinterpret_cast<const unsigned char*>( login->username ), user_len
	);

	// Convert the 32 bytes to 64 chars
	char hex[65];
	sodium_bin2hex( hex, sizeof( hex ), hash, sizeof( hash ) );

	// Build the replacement packet
	PACKET_CA_LOGIN_HASHED packet;
	memset( &packet, 0, sizeof( packet ) );
	packet.packetType = HEADER_CA_LOGIN_HASHED;
	memcpy( packet.username, login->username, sizeof( packet.username ) );
	memcpy( packet.passwordHash, hex, sizeof( packet.passwordHash ) );

	// Send the hashed packet, return original len to trick the client
	int result = real_send( s, reinterpret_cast<const char*>( &packet ), sizeof( packet ), flags );
	if ( result > 0 )
		return len;

	return result;
}
