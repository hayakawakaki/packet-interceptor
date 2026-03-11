#include <winsock2.h>
#include <windows.h>
#include <sodium.h>

#include "packet_def.hpp"
#include "packet.hpp"
#include "handler.hpp"

static SEND_FN original_send = nullptr;

static int WINAPI send_intercept( SOCKET s, const char *buf, int len, int flags ) {
	int result = packet_handler_dispatch( s, buf, len, flags, original_send );
	if ( result != -1 )
		return result;

	return original_send( s, buf, len, flags );
}

static bool hook_send() {
	HMODULE ws2 = GetModuleHandleA( "ws2_32.dll" );
	if ( ws2 == nullptr )
		return false;

	auto *target = reinterpret_cast<unsigned char*>( GetProcAddress( ws2, "send" ) );
	if ( target == nullptr )
		return false;

	// Allocate executable memory for the trampoline
	auto *trampoline = reinterpret_cast<unsigned char*>( VirtualAlloc( nullptr, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE ) );
	if ( trampoline == nullptr )
		return false;

	// Copy the function prologue into the trampoline
	memcpy( trampoline, target, 5 );

	// Append a JMP back to send+5 to continue the original send
	trampoline[5] = 0xE9;
	*reinterpret_cast<int*>( trampoline + 6 ) = reinterpret_cast<int>( target + 5 ) - reinterpret_cast<int>( trampoline + 5 ) - 5;

	original_send = reinterpret_cast<SEND_FN>( trampoline );

	// Overwrite send first 5 bytes with a JMP (0xE9) to send_intercept
	DWORD og_protect;
	VirtualProtect( target, 5, PAGE_EXECUTE_READWRITE, &og_protect );
	target[0] = 0xE9;
	*reinterpret_cast<int*>( target + 1 ) = reinterpret_cast<int>( send_intercept ) - reinterpret_cast<int>( target ) - 5;
	VirtualProtect( target, 5, og_protect, &og_protect );

	return true;
}

static void register_handlers() {
	packet_handler_register( HEADER_CA_LOGIN, handle_login );
}

// Initialize required libraries and install hooks
static bool init() {
	if ( sodium_init() == -1 )
		return false;

	register_handlers();

	return hook_send();
}

// Dummy — CFF Explorer needs a real function name to add this DLL to the PE import table
extern "C" __declspec(dllexport) void interceptor_init( void ) {}

// Entrypoint
BOOL WINAPI DllMain( HINSTANCE dll_instance, DWORD fdw_reason, LPVOID ) {
	if ( fdw_reason == DLL_PROCESS_ATTACH ) {
		DisableThreadLibraryCalls( dll_instance );
		return init();
	}
	return TRUE;
}
