#if defined(DM_PLATFORM_IOS)

#include "siwa.h"
#include <dmsdk/sdk.h>

#define MODULE_NAME "siwa"

SiwaData g_SiwaData;
SiwaCallbackData g_SiwaCallbackData;

char* Siwa_GetUserId()
{
    return g_SiwaData.m_userID;
}

void Siwa_ResetCallbackData()
{
    free(g_SiwaCallbackData.m_userID);
    g_SiwaCallbackData.m_userID = 0;
    free(g_SiwaCallbackData.m_identityToken);
    g_SiwaCallbackData.m_identityToken = 0;
    free(g_SiwaCallbackData.m_userID);
    g_SiwaCallbackData.m_userID = 0;
    free(g_SiwaCallbackData.m_email);
    g_SiwaCallbackData.m_email = 0;
    free(g_SiwaCallbackData.m_firstName);
    g_SiwaCallbackData.m_firstName = 0;
    free(g_SiwaCallbackData.m_familyName);
    g_SiwaCallbackData.m_familyName = 0;
    free(g_SiwaCallbackData.m_identityToken);
    g_SiwaCallbackData.m_identityToken = 0;
    free(g_SiwaCallbackData.m_message);
    g_SiwaCallbackData.m_message = 0;

    g_SiwaCallbackData.m_userStatus = -1;
    g_SiwaCallbackData.m_state = STATE_UNKNOWN;
    g_SiwaCallbackData.m_cmd = CMD_NONE;
}

void Siwa_QueueCredentialCallback(char* userID, SiwaCredentialState state)
{
    if(g_SiwaCallbackData.m_cmd != CMD_NONE) {
        dmLogError("Can't queue credential callback, already have a callback queued!");
        return;
    }

    g_SiwaCallbackData.m_cmd = CMD_CREDENTIAL;
    g_SiwaCallbackData.m_userID = strdup(userID);
    g_SiwaCallbackData.m_state = state;
}


void Siwa_QueueAuthSuccessCallback(const char* identityToken, const char* userID, const char* email, const char* firstName, const char* familyName, int userStatus)
{
    if(g_SiwaCallbackData.m_cmd != CMD_NONE) {
        dmLogError("Can't queue auth success callback, already have a callback queued!");
        return;
    }

    g_SiwaCallbackData.m_cmd = CMD_AUTH_SUCCESS;
    g_SiwaCallbackData.m_identityToken = strdup(identityToken);
    g_SiwaCallbackData.m_userID = strdup(userID);
    g_SiwaCallbackData.m_email = strdup(email != 0 ? email: "");
    g_SiwaCallbackData.m_firstName = strdup(firstName != 0 ? firstName: "");
    g_SiwaCallbackData.m_familyName = strdup(familyName != 0 ? familyName : "");
    g_SiwaCallbackData.m_userStatus = userStatus;
    g_SiwaCallbackData.m_message = strdup("");
}

void Siwa_QueueAuthFailureCallback(const char* message)
{
    if(g_SiwaCallbackData.m_cmd != CMD_NONE) {
        dmLogError("Can't queue auth error callback, already have a callback queued!");
        return;
    }

    g_SiwaCallbackData.m_cmd = CMD_AUTH_FAILED;
    g_SiwaCallbackData.m_message = strdup(message);
}


void Siwa_TriggerCallback()
{
    lua_State* L = dmScript::GetCallbackLuaContext(g_SiwaData.m_callback);
    DM_LUA_STACK_CHECK(L, 0);

    if (dmScript::SetupCallback(g_SiwaData.m_callback))
    {
        lua_createtable(L, 0, 3);

        if (g_SiwaCallbackData.m_cmd == CMD_CREDENTIAL)
        {
            lua_pushstring(L, "result");
            lua_pushstring(L, "SUCCESS");
            lua_settable(L, -3);

            lua_pushstring(L, "user_id");
            lua_pushstring(L, g_SiwaCallbackData.m_userID);
            lua_settable(L, -3);

            lua_pushstring(L, "credential_state");
            lua_pushnumber(L, g_SiwaCallbackData.m_state);
            lua_settable(L, -3);
        }
        else if (g_SiwaCallbackData.m_cmd == CMD_AUTH_SUCCESS)
        {
            lua_pushstring(L, "result");
            lua_pushstring(L, "SUCCESS");
            lua_settable(L, -3);

            lua_pushstring(L, "identity_token");
            lua_pushstring(L, g_SiwaCallbackData.m_identityToken);
            lua_settable(L, -3);

            lua_pushstring(L, "user_id");
            lua_pushstring(L, g_SiwaCallbackData.m_userID);
            lua_settable(L, -3);

            lua_pushstring(L, "email");
            lua_pushstring(L, g_SiwaCallbackData.m_email);
            lua_settable(L, -3);

            lua_pushstring(L, "first_name");
            lua_pushstring(L, g_SiwaCallbackData.m_firstName);
            lua_settable(L, -3);

            lua_pushstring(L, "family_name");
            lua_pushstring(L, g_SiwaCallbackData.m_familyName);
            lua_settable(L, -3);

            lua_pushstring(L, "user_status");
            lua_pushnumber(L, g_SiwaCallbackData.m_userStatus);
            lua_settable(L, -3);
        }
        else if (g_SiwaCallbackData.m_cmd == CMD_AUTH_FAILED)
        {
            lua_pushstring(L, "result");
            lua_pushstring(L, "ERROR");
            lua_settable(L, -3);

            lua_pushstring(L, "message");
            lua_pushstring(L, g_SiwaCallbackData.m_message);
            lua_settable(L, -3);
        }

        if (lua_pcall(L, 2, 0, 0) != 0)
        {
            dmLogError("Error running siwa callback: %s", lua_tostring(L, -1));
            lua_pop(L, 1);
        }
        dmScript::TeardownCallback(g_SiwaData.m_callback);
    }
}


void Siwa_SetupCallback(lua_State* L, int index)
{
    if (g_SiwaData.m_callback) {
        dmScript::DestroyCallback(g_SiwaData.m_callback);
    }
    g_SiwaData.m_callback = dmScript::CreateCallback(L, index);
}

void Siwa_CleanupCallback() {
    if (g_SiwaData.m_callback) {
        dmScript::DestroyCallback(g_SiwaData.m_callback);
        g_SiwaData.m_callback = 0;
    }
}

int Siwa_GetCredentialState(lua_State* L){
    DM_LUA_STACK_CHECK(L, 1);

    if (!Siwa_PlatformIsSupported()) {
        dmLogWarning("Sign in with Apple is not available");
        lua_pushboolean(L, 0);
        return 1;
    }

    if(g_SiwaData.m_callback != 0)
    {
        dmLogError("Callback already in progress");
        lua_pushboolean(L, 0);
        return 1;
    }

    luaL_checktype(L, 1, LUA_TSTRING);
    if (g_SiwaData.m_userID) free(g_SiwaData.m_userID);
    g_SiwaData.m_userID = strdup(lua_tostring(L, 1));

    luaL_checktype(L, 2, LUA_TFUNCTION);
    Siwa_SetupCallback(L, 2);
    Siwa_PlatformGetCredentialState();

    lua_pushboolean(L, 1);
    return 1;
}

int Siwa_AuthenticateWithApple(lua_State* L) {
    DM_LUA_STACK_CHECK(L, 1);

    if (!Siwa_PlatformIsSupported()) {
        dmLogWarning("Sign in with Apple is not available");
        lua_pushboolean(L, 0);
        return 1;
    }

    if(g_SiwaData.m_callback != 0)
    {
        dmLogError("Callback already in progress");
        lua_pushboolean(L, 0);
        return 1;
    }

    luaL_checktype(L, 1, LUA_TFUNCTION);
    Siwa_SetupCallback(L, 1);
    Siwa_PlatformAuthenticateWithApple();

    lua_pushboolean(L, 1);
    return 1;
}

int Siwa_IsSupported(lua_State* L) {
    DM_LUA_STACK_CHECK(L, 1);
    lua_pushboolean(L, Siwa_PlatformIsSupported());
    return 1;
}

static dmExtension::Result SiwaAppInitialize(dmExtension::AppParams* params)
{
    Siwa_ResetCallbackData();
    return dmExtension::RESULT_OK;
}

static dmExtension::Result SiwaAppFinalize(dmExtension::AppParams* params)
{
    return dmExtension::RESULT_OK;
}

const luaL_reg lua_register[] =
{
    {"is_supported", Siwa_IsSupported},
    {"get_credential_state", Siwa_GetCredentialState},
    {"authenticate", Siwa_AuthenticateWithApple},
    {0, 0}
};

static dmExtension::Result SiwaInitialize(dmExtension::Params* params)
{
    lua_State* L = params->m_L;
    int top = lua_gettop(L);
    luaL_register(L, MODULE_NAME, lua_register);

    #define SETCONSTANT(name) \
            lua_pushnumber(L, (lua_Number) name); \
            lua_setfield(L, -2, #name);\

        SETCONSTANT(STATE_NOT_FOUND)
        SETCONSTANT(STATE_UNKNOWN)
        SETCONSTANT(STATE_AUTHORIZED)
        SETCONSTANT(STATE_REVOKED)

    #undef SETCONSTANT

    lua_pop(L, 1);
    assert(top == lua_gettop(L));
    return dmExtension::RESULT_OK;
}

static dmExtension::Result SiwaUpdate(dmExtension::Params* params)
{
    if(g_SiwaCallbackData.m_cmd != CMD_NONE)
    {
        Siwa_TriggerCallback();
        Siwa_ResetCallbackData();
        Siwa_CleanupCallback();
    }
    return dmExtension::RESULT_OK;
}

static dmExtension::Result SiwaFinalize(dmExtension::Params* params)
{
    return dmExtension::RESULT_OK;
}

DM_DECLARE_EXTENSION(siwa, MODULE_NAME, SiwaAppInitialize, SiwaAppFinalize, SiwaInitialize, SiwaUpdate, 0, SiwaFinalize);

#endif
