#pragma once
#if defined(DM_PLATFORM_IOS)

struct lua_State;

namespace siwa_code {
namespace platform {

    // Standard Defold Native Extension functions
    void AppInitialize();
    void AppFinalize();
    void Initialize();
    void Update();
    void Finalize();

    // Trigged by a call from lua to check if sign in with apple is supported on this device.
    int IsSiwaSupported(lua_State* L);

    // Triggered by a call from lua to start the sign in with apple flow
    // expects the callback to be a reference number to the lua registry
    // expects the context to be reference number to the lua registry
    int AuthenticateWithApple(lua_State* L, int callback, int context, lua_State* thread);

    // Triggered by a call from lua to check if a provided apple id grants this app permission to use that id.
    // expects the callback to be a reference number to the lua registry
    // expects the context to be reference number to the lua registry
    int CheckStatusOfAppleID(lua_State* L, char* userID, int callback, int context, lua_State* thread);


} // namespace
} // namespace

#endif
