#pragma once

#include "packet.hpp"

int handle_login( SOCKET s, const char *buf, int len, int flags, SEND_FN real_send );
