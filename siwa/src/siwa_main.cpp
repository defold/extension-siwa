#if defined(DM_PLATFORM_IOS)

#include "siwa_ios.h"
#include <dmsdk/extension/extension.h>
#include <dmsdk/script/script.h>
#include <dmsdk/dlib/log.h>
#include <assert.h>
#include <iostream>


#define MODULE_NAME "siwa"

namespace siwa_code {

static int ReturnFalse(lua_State* L) {
    DM_LUA_STACK_CHECK(L, 1);
    lua_pushboolean(L, 0);
    return 1;
}

static int ReturnNil(lua_State* L){
    DM_LUA_STACK_CHECK(L, 1);
    lua_pushnil(L);
    return 1;
}

// Function for asking Apple if a provided user id currently grants us access to it for this app.
// Expects: (a string containing the user id, and a callback that expects a self instance and a table containing results).
// The callback will be triggered at some point later after getting a response from Apple.
// The response will be SUCCESS whether or not the id granted us permission.
// It will give us a status of 1 if the user is authorized, and 2 if it's not.
static int CheckStatusOfAppleID(lua_State* L){
    DM_LUA_STACK_CHECK(L, 0);

    int num_args = lua_gettop(L);
    if(num_args != 2){
        dmLogError("Incorrect number of args passed to CheckStatusOfAppleID!");
        return ReturnFalse(L);
    }

    luaL_checktype(L, 1, LUA_TSTRING);
    char* userID = strdup(lua_tostring(L, 1));

    luaL_checktype(L, 2, LUA_TFUNCTION);
    lua_pushvalue(L, 2);
    int callback = dmScript::Ref(L, LUA_REGISTRYINDEX);

    dmScript::GetInstance(L);
    int context = dmScript::Ref(L, LUA_REGISTRYINDEX);

    lua_State* thread = dmScript::GetMainThread(L);

    if (platform::IsSiwaSupported(L)) {
        platform::CheckStatusOfAppleID(L, userID, callback, context, thread);
    }

    return 0;
}

// Function for having a user sign in with Apple.
// Expects: (a callback that expects a self instance and a table containing results).
// The callback will be triggered at some point later after getting a response from Apple.
// The first time a user signs in after granting permission to this app, the callback will give us a name and email
// as well as a user id and identity token on success.
// On subsequent logins, we will only get the user id and identity token.
// On a failure, such as when the user cancels the login flow, we will get ERROR as a result, and a message
// describing the error.
static int AuthenticateWithApple(lua_State* L){
    DM_LUA_STACK_CHECK(L, 0);

    luaL_checktype(L, 1, LUA_TFUNCTION);

    lua_pushvalue(L, 1);
    int callback = dmScript::Ref(L, LUA_REGISTRYINDEX);

    dmScript::GetInstance(L);
    int context = dmScript::Ref(L, LUA_REGISTRYINDEX);

    lua_State* thread = dmScript::GetMainThread(L);

    if (platform::IsSiwaSupported(L)) {
        platform::AuthenticateWithApple(L, callback, context, thread);
    }

    return 0;
}

const luaL_reg lua_register[] =
{
    {"is_siwa_supported", platform::IsSiwaSupported},
    {"check_credentials_status", CheckStatusOfAppleID},
    {"authenticate", AuthenticateWithApple},
    {0, 0}
};

static dmExtension::Result AppInitialize(dmExtension::AppParams* params)
{
    platform::AppInitialize();
    return dmExtension::RESULT_OK;
}

static dmExtension::Result AppFinalize(dmExtension::AppParams* params)
{
    platform::AppFinalize();
    return dmExtension::RESULT_OK;
}

static dmExtension::Result Initialize(dmExtension::Params* params)
{
    // Register lua functions
    {
        lua_State* L = params->m_L;
        int top = lua_gettop(L);
        luaL_register(L, MODULE_NAME, lua_register);
        lua_pop(L, 1);
        assert(top == lua_gettop(L));
    }

    platform::Initialize();
    return dmExtension::RESULT_OK;
}

static dmExtension::Result Update(dmExtension::Params* params)
{
    platform::Update();
    return dmExtension::RESULT_OK;
}

static dmExtension::Result Finalize(dmExtension::Params* params)
{
    platform::Finalize();
    return dmExtension::RESULT_OK;
}

} // namespace

DM_DECLARE_EXTENSION(siwa, MODULE_NAME, siwa_code::AppInitialize, siwa_code::AppFinalize, siwa_code::Initialize, siwa_code::Update, 0, siwa_code::Finalize);

#endif
