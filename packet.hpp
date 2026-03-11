#pragma once

#include <winsock2.h>
#include <cstdint>

typedef int (WINAPI *SEND_FN)( SOCKET s, const char *buf, int len, int flags );
typedef int (*PACKET_FN)( SOCKET s, const char *buf, int len, int flags, SEND_FN original_send );

struct s_packet_entry {
	int16_t opcode;
	PACKET_FN handler;
};

void packet_handler_register( int16_t opcode, PACKET_FN handler );
int  packet_handler_dispatch( SOCKET s, const char *buf, int len, int flags, SEND_FN original_send );
