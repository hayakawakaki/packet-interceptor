# Packet Interceptor

A Win32 hook for the ro client's `send()` function to intercept and transform outgoing network packets before they reach the target server.

## How It Works
1. On `DllMain(DLL_PROCESS_ATTACH)`, the hook installs an inline detour hook on `ws2_32.dll's send()`
2. Every outgoing `send()` call passes through `send_intercept()`, which reads the 2-byte opcode
3. Matching opcodes are dispatched to handler functions, unmatched packets continues to the original `send()`

## Included Sample
- Login packet handler intercepts `CA_LOGIN` (0x0064), hashes the plaintext password with BLAKE2b-256 using the username as the key, and sends the replacement packet `CA_LOGIN_HASHED` (0x0C50) to the server.

## Building
1. Open `interceptor.vcxproj` in Visual Studio 2022
2. Select **Release | Win32**
3. Build — outputs `interceptor.dll` to `build/`

## Installation
### [Warp](https://github.com/hiphop9/Warp2025)
1. Add the following to `DLLSpec.yml`:
```yml
Name: interceptor.dll
Funcs:
  - Name: "interceptor_init"
  - Ordinal: 1
```
2. Enable the **Add custom DLLs** patch

### [CFF Explorer](https://ntcore.com/explorer-suite/)
1. Open the game executable in CFF Explorer
2. Go to **Import Adder**
3. Browse and select `interceptor.dll`
4. Select the `interceptor_init` function from the export list
5. Click **Add** then **Rebuild Import Table**
6. Save the patched executable

## Adding New Packet Handlers
1. Define the original and replacement packet structs in `packets.hpp`
2. Write a handler function in `handler.hpp/cpp`
3. Add a `case` to the switch in `send_intercept()` in `interceptor.cpp`

### Build Requirements
- Visual Studio 2022
- C++17

## Tested Client Compatibility
2025-06-04

## Disclaimer
Use at your own risk.

## Credits
- [rAthena](https://github.com/rathena/rathena) — for the packet structures and base type definitions
- [skylove](https://github.com/hiphop9) - for the client and for the updated warp
