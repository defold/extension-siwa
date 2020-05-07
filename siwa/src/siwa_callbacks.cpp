#include "siwa_callbacks.h"

#if defined(DM_PLATFORM_IOS)

#include <dmsdk/dlib/log.h>
#include <dmsdk/dlib/mutex.h>
#include <dmsdk/script/script.h>

#include <stdlib.h>
#include <string.h>

namespace dmSiwa {

    // access to these structs should be protected by mutex
    // as they are used by callbacks that can trigger in arbitrary contexts.
    static CredentialCallbackData g_CredentialCallbackData;
    static AuthCallbackData g_AuthCallbackData;

    static dmMutex::HMutex g_CredentialCallbackMutex;
    static dmMutex::HMutex g_AuthCallbackMutex;
}

void dmSiwa::InitCallbacks()
{
    InitCredentialCallbackData();
    InitAuthCallbackData();
}

void dmSiwa::CheckForQueuedCallbacks()
{
    CheckForCredentialCallback();
    CheckForAuthCallback();
}

// do the common setup for lua callbacks for this extension
bool dmSiwa::RunCallbackSetup(lua_State* L, int _self, int _callback)
{
    if (_callback != LUA_NOREF)
    {
        lua_rawgeti(L, LUA_REGISTRYINDEX, _callback);
        lua_rawgeti(L, LUA_REGISTRYINDEX, _self);
        lua_pushvalue(L, -1);
        dmScript::SetInstance(L);
        return true;
    }
    else
    {
        dmLogError("No callback set for siwa");
        return false;
    }
}

//==================================================================
// Callback for checking the credential state of a provided sign in with Apple ID
//==================================================================
void dmSiwa::InitCredentialCallbackData()
{
    g_CredentialCallbackMutex = dmMutex::New();
    ResetCredentialCallbackData();
}

void dmSiwa::ResetCredentialCallbackData()
{
    DM_MUTEX_SCOPED_LOCK(g_CredentialCallbackMutex)
    g_CredentialCallbackData.m_L = nullptr;
    g_CredentialCallbackData.m_self = LUA_NOREF;
    g_CredentialCallbackData.m_callback = LUA_NOREF;
    g_CredentialCallbackData.m_userID = nullptr;
    g_CredentialCallbackData.m_status = -1;

    g_CredentialCallbackData.m_cbState = IDLE;
}

void dmSiwa::QueueCredentialCallback(lua_State* L, int _self, int _callback, char* _userID, int status)
{
    DM_MUTEX_SCOPED_LOCK(g_CredentialCallbackMutex)
    if(g_CredentialCallbackData.m_cbState != IDLE){
        dmLogError("Can't queue credential callback, already queued or running!");
        return;
    }

    g_CredentialCallbackData.m_L = L;
    g_CredentialCallbackData.m_self = _self;
    g_CredentialCallbackData.m_callback = _callback;
    g_CredentialCallbackData.m_userID = strdup(_userID);
    g_CredentialCallbackData.m_status = status;

    g_CredentialCallbackData.m_cbState = QUEUED;
}

void dmSiwa::RunCredentialCallback()
{
    lua_State* L = nullptr;
    int _self = LUA_NOREF;
    int _callback = LUA_NOREF;
    char* _userID = nullptr;
    int status = -1;

    {
        DM_MUTEX_SCOPED_LOCK(g_CredentialCallbackMutex)

        L = g_CredentialCallbackData.m_L;

        _self = g_CredentialCallbackData.m_self;
        g_CredentialCallbackData.m_self = LUA_NOREF;

        _callback = g_CredentialCallbackData.m_callback;
        g_CredentialCallbackData.m_callback = LUA_NOREF;

        if(g_CredentialCallbackData.m_userID != nullptr)
        {
            _userID = strdup(g_CredentialCallbackData.m_userID);
            free(g_CredentialCallbackData.m_userID);
            g_CredentialCallbackData.m_userID = nullptr;
        }

        status = g_CredentialCallbackData.m_status;
    }

    // if the pre setup fails, bail
    if(L == nullptr or _self == LUA_NOREF or _callback == LUA_NOREF or _userID == nullptr
        or !RunCallbackSetup(L, _self, _callback))
    {
        dmLogError("Could not run siwa credential callback because a parameter was null or missing");
        lua_pop(L, 2);
        return;
    }

    if (dmScript::IsInstanceValid(L))
    {
        lua_createtable(L, 0, 3);

        lua_pushstring(L, "result");
        lua_pushstring(L, "SUCCESS");
        lua_settable(L, -3);

        lua_pushstring(L, "user_id");
        lua_pushstring(L, _userID);
        lua_settable(L, -3);

        lua_pushstring(L, "credential_status");
        lua_pushnumber(L, status);
        lua_settable(L, -3);

        if (lua_pcall(L, 2, 0, 0) != 0)
        {
            dmLogError("Error running siwa credential callback: %s", lua_tostring(L, -1));
            lua_pop(L, 1);
        }

        free(_userID);
        dmScript::Unref(L, LUA_REGISTRYINDEX, _callback);
        dmScript::Unref(L, LUA_REGISTRYINDEX, _self);
    }
    else
    {
        dmLogError("Could not run siwa credential callback because the instance is invalid.");
        lua_pop(L, 2);
    }
}

void dmSiwa::CheckForCredentialCallback()
{
    bool triggerCallback = false;
    {
        DM_MUTEX_SCOPED_LOCK(g_CredentialCallbackMutex)
        if(g_CredentialCallbackData.m_cbState == QUEUED)
        {
            triggerCallback = true;
            g_CredentialCallbackData.m_cbState = RUNNING;
        }
    }

    if(triggerCallback)
    {
        RunCredentialCallback();
        ResetCredentialCallbackData();
    }
}

//==================================================================
// Callback for the sign in with Apple ID
//==================================================================

void dmSiwa::InitAuthCallbackData()
{
    g_AuthCallbackMutex = dmMutex::New();
    ResetAuthCallbackData();
}

void dmSiwa::ResetAuthCallbackData()
{
    DM_MUTEX_SCOPED_LOCK(g_AuthCallbackMutex)
    g_AuthCallbackData.m_L = nullptr;
    g_AuthCallbackData.m_self = LUA_NOREF;
    g_AuthCallbackData.m_callback = LUA_NOREF;

    g_AuthCallbackData.m_identityToken = nullptr;
    g_AuthCallbackData.m_userID = nullptr;
    g_AuthCallbackData.m_email = nullptr;
    g_AuthCallbackData.m_firstName = nullptr;
    g_AuthCallbackData.m_familyName = nullptr;

    g_AuthCallbackData.m_userStatus = -1;

    g_AuthCallbackData.m_message = nullptr;

    g_AuthCallbackData.m_cbState = IDLE;
    g_AuthCallbackData.m_success = false;
}

void dmSiwa::QueueAuthSuccessCallback(lua_State* L, int _self, int _callback, const char* identityToken, const char* userID, const char* email, const char* firstName, const char* familyName, int userStatus)
{
    DM_MUTEX_SCOPED_LOCK(g_AuthCallbackMutex)
    if(g_AuthCallbackData.m_cbState != IDLE){
        dmLogError("Can't queue auth success callback, already queued or running!");
        return;
    }

    g_AuthCallbackData.m_L = L;
    g_AuthCallbackData.m_self = _self;
    g_AuthCallbackData.m_callback = _callback;

    if(identityToken != nullptr)
    {
        g_AuthCallbackData.m_identityToken = strdup(identityToken);
    }

    if(userID != nullptr)
    {
        g_AuthCallbackData.m_userID = strdup(userID);
    }

    if(email != nullptr)
    {
        g_AuthCallbackData.m_email = strdup(email);
    }

    if(firstName != nullptr)
    {
        g_AuthCallbackData.m_firstName = strdup(firstName);
    }

    if(familyName != nullptr)
    {
        g_AuthCallbackData.m_familyName = strdup(familyName);
    }

    g_AuthCallbackData.m_userStatus = userStatus;

    g_AuthCallbackData.m_message = nullptr;

    g_AuthCallbackData.m_cbState = QUEUED;
    g_AuthCallbackData.m_success = true;
}

void dmSiwa::QueueAuthFailureCallback(lua_State* L, int _self, int _callback, const char* message)
{
    DM_MUTEX_SCOPED_LOCK(g_AuthCallbackMutex)
    if(g_AuthCallbackData.m_cbState != IDLE){
        dmLogError("Can't queue auth error callback, already queued or running!");
        return;
    }

    g_AuthCallbackData.m_L = L;
    g_AuthCallbackData.m_self = _self;
    g_AuthCallbackData.m_callback = _callback;

    g_AuthCallbackData.m_message = strdup(message);

    g_AuthCallbackData.m_cbState = QUEUED;
    g_AuthCallbackData.m_success = false;
}

void dmSiwa::CheckForAuthCallback()
{
    bool triggerCallback = false;
    bool success = false;
    {
        DM_MUTEX_SCOPED_LOCK(g_AuthCallbackMutex)
        if(g_AuthCallbackData.m_cbState == QUEUED)
        {
            triggerCallback = true;
            success = g_AuthCallbackData.m_success;
            g_AuthCallbackData.m_cbState = RUNNING;
        }
    }

    if(triggerCallback)
    {
        if(success)
        {
            RunAuthSuccessCallback();
        }
        else
        {
            RunAuthFailureCallback();
        }

        ResetAuthCallbackData();
    }
}

void dmSiwa::RunAuthSuccessCallback()
{
    lua_State* L = nullptr;
    int _self = LUA_NOREF;
    int _callback = LUA_NOREF;

    char* identityToken = nullptr;
    char* userID = nullptr;
    char* email = nullptr;
    char* firstName = nullptr;
    char* familyName = nullptr;
    int userStatus = -1;
    {
        DM_MUTEX_SCOPED_LOCK(g_AuthCallbackMutex);
        L = g_AuthCallbackData.m_L;
        userStatus = g_AuthCallbackData.m_userStatus;
        g_AuthCallbackData.m_L = nullptr;

        // take ownership of auth data
        _self = g_AuthCallbackData.m_self;
        g_AuthCallbackData.m_self = LUA_NOREF;

        _callback = g_AuthCallbackData.m_callback;
        g_AuthCallbackData.m_callback = LUA_NOREF;

        if(g_AuthCallbackData.m_identityToken != nullptr)
        {
            identityToken = strdup(g_AuthCallbackData.m_identityToken);
            free(g_AuthCallbackData.m_identityToken);
            g_AuthCallbackData.m_identityToken = nullptr;
        }

        if(g_AuthCallbackData.m_userID != nullptr)
        {
            userID = strdup(g_AuthCallbackData.m_userID);
            free(g_AuthCallbackData.m_userID);
            g_AuthCallbackData.m_userID = nullptr;
        }

        if(g_AuthCallbackData.m_email != nullptr)
        {
            email = strdup(g_AuthCallbackData.m_email);
            free(g_AuthCallbackData.m_email);
            g_AuthCallbackData.m_email = nullptr;
        }

        if(g_AuthCallbackData.m_firstName != nullptr)
        {
            firstName = strdup(g_AuthCallbackData.m_firstName);
            free(g_AuthCallbackData.m_firstName);
            g_AuthCallbackData.m_firstName = nullptr;
        }

        if(g_AuthCallbackData.m_familyName != nullptr)
        {
            familyName = strdup(g_AuthCallbackData.m_familyName);
            free(g_AuthCallbackData.m_familyName);
            g_AuthCallbackData.m_familyName = nullptr;
        }
    }

    // if the pre setup fails, bail
    // first name, family name, and email can be null in normal execution, as they are not provided
    // after a user's first login to our app. Userid and identity token should always be provided.
    if(L == nullptr or _self == LUA_NOREF or _callback == LUA_NOREF or identityToken == nullptr or userID == nullptr
        or !RunCallbackSetup(L, _self, _callback))
    {
        dmLogError("Could not run siwa auth success callback because a parameter was null or missing");

        free(identityToken);
        free(userID);
        free(email);
        free(firstName);
        free(familyName);

        if(_self != LUA_NOREF)
        {
            dmScript::Unref(L, LUA_REGISTRYINDEX, _self);
        }

        if(_callback != LUA_NOREF)
        {
            dmScript::Unref(L, LUA_REGISTRYINDEX, _callback);
        }

        lua_pop(L, 2);
        return;
    }

    if (dmScript::IsInstanceValid(L))
    {
        lua_createtable(L, 0, 7);

        lua_pushstring(L, "result");
        lua_pushstring(L, "SUCCESS");
        lua_settable(L, -3);

        lua_pushstring(L, "identity_token");
        lua_pushstring(L, identityToken);
        lua_settable(L, -3);

        lua_pushstring(L, "user_id");
        lua_pushstring(L, userID);
        lua_settable(L, -3);

        lua_pushstring(L, "email");
        lua_pushstring(L, email);
        lua_settable(L, -3);

        lua_pushstring(L, "first_name");
        lua_pushstring(L, firstName);
        lua_settable(L, -3);

        lua_pushstring(L, "family_name");
        lua_pushstring(L, familyName);
        lua_settable(L, -3);

        lua_pushstring(L, "user_status");
        lua_pushnumber(L, userStatus);
        lua_settable(L, -3);

        if (lua_pcall(L, 2, 0, 0) != 0)
        {
            dmLogError("Error running siwa auth success callback: %s", lua_tostring(L, -1));
            lua_pop(L, 1);
        }

        // clean up owned data
        free(identityToken);
        free(userID);
        free(email);
        free(firstName);
        free(familyName);

        dmScript::Unref(L, LUA_REGISTRYINDEX, _callback);
        dmScript::Unref(L, LUA_REGISTRYINDEX, _self);
    }
    else
    {
        dmLogError("Could not run siwa auth success callback because the instance is invalid.");
        lua_pop(L, 2);
    }
}

void dmSiwa::RunAuthFailureCallback()
{
    lua_State* L = nullptr;
    int _self = LUA_NOREF;
    int _callback = LUA_NOREF;

    char* message = nullptr;
    {
        DM_MUTEX_SCOPED_LOCK(g_AuthCallbackMutex)
        L = g_AuthCallbackData.m_L;

        // take ownership of authorization data
        _self = g_AuthCallbackData.m_self;
        g_AuthCallbackData.m_self = LUA_NOREF;

        _callback = g_AuthCallbackData.m_callback;
        g_AuthCallbackData.m_callback = LUA_NOREF;

        if(g_AuthCallbackData.m_message != nullptr)
        {
            message = strdup(g_AuthCallbackData.m_message);
            free(g_AuthCallbackData.m_message);
            g_AuthCallbackData.m_message = nullptr;
        }
    }

    // if the pre setup fails, bail
    if(L == nullptr or _self == LUA_NOREF or _callback == LUA_NOREF or message == nullptr
        or !RunCallbackSetup(L, _self, _callback))
    {
        dmLogError("Could not run siwa auth error callback because a parameter was null or missing");

        free(message);

        if(_self != LUA_NOREF)
        {
            dmScript::Unref(L, LUA_REGISTRYINDEX, _self);
        }

        if(_callback != LUA_NOREF)
        {
            dmScript::Unref(L, LUA_REGISTRYINDEX, _callback);
        }

        lua_pop(L, 2);
        return;
    }

    if (dmScript::IsInstanceValid(L))
    {
        lua_createtable(L, 0, 2);

        lua_pushstring(L, "result");
        lua_pushstring(L, "ERROR");
        lua_settable(L, -3);

        lua_pushstring(L, "message");
        lua_pushstring(L, message);
        lua_settable(L, -3);

        if (lua_pcall(L, 2, 0, 0) != 0)
        {
            dmLogError("Error running siwa auth error callback: %s", lua_tostring(L, -1));
            lua_pop(L, 1);
        }

        free(message);
        dmScript::Unref(L, LUA_REGISTRYINDEX, _callback);
        dmScript::Unref(L, LUA_REGISTRYINDEX, _self);
    }
    else
    {
        dmLogError("Could not run siwa auth error callback because the instance is invalid.");

        free(message);
        dmScript::Unref(L, LUA_REGISTRYINDEX, _callback);
        dmScript::Unref(L, LUA_REGISTRYINDEX, _self);

         // We need to clean up our stack, which has 2 elements at this point (see comment 4:)
         lua_pop(L, 2);
    }
}

#endif
