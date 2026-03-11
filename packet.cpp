#include "packet.hpp"

#include <vector>
#include <cstdio>

static std::vector<s_packet_entry> handlers;

void packet_handler_register( int16_t opcode, PACKET_FN handler ) {
	for ( const auto &entry : handlers ) {
		if ( entry.opcode == opcode ) {
			char msg[128];
			snprintf( msg, sizeof( msg ), "Duplicate packet handler: 0x%04X", opcode );
			MessageBoxA( nullptr, msg, "interceptor", MB_OK | MB_ICONERROR );
			abort();
		}
	}

	handlers.push_back( { opcode, handler } );
}

int packet_handler_dispatch( SOCKET s, const char *buf, int len, int flags, SEND_FN original_send ) {
	if ( len < 2 )
		return -1;

	int16_t opcode = *reinterpret_cast<const int16_t *>( buf );

	for ( const auto &entry : handlers ) {
		if ( entry.opcode == opcode )
			return entry.handler( s, buf, len, flags, original_send );
	}

	return -1;
}
