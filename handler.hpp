#pragma once

#include <winsock2.h>

typedef int (WINAPI *SEND_FN)( SOCKET s, const char *buf, int len, int flags );

int handle_login( SOCKET s, const char *buf, int len, int flags, SEND_FN real_send );
