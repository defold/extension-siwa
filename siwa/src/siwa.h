#pragma once
#if defined(DM_PLATFORM_IOS)

#include <dmsdk/sdk.h>

enum SiwaCallbackCmd
{
	CMD_NONE = 0,
	CMD_CREDENTIAL = 1,
	CMD_AUTH_SUCCESS = 2,
	CMD_AUTH_FAILED = 3
};

enum SiwaCredentialState
{
	STATE_UNKNOWN = 0,
	STATE_AUTHORIZED = 1,
	STATE_REVOKED = 2,
	STATE_NOT_FOUND = 3
};

struct SiwaCallbackData
{
	SiwaCallbackData()
	{
		memset(this, 0, sizeof(*this));
	};

	SiwaCallbackCmd m_cmd;
	SiwaCredentialState m_state;

	char* m_identityToken;
	char* m_userID;
	char* m_email;
	char* m_firstName;
	char* m_familyName;
	int m_userStatus;

	char* m_message;
};

// Data used to ensure we only have 1 request in progress with Apples servers at a time.
// Access should be restricted behind mutex protection as the callbacks from apple can
// be triggered in arbitrary contexts.
// This data is also used to hold information passed from lua until the callback comes
// back from Apple, so that we may pass it back to lua to identify the request we are
// getting a callback for.
struct SiwaData
{
    SiwaData()
	{
        memset(this, 0, sizeof(*this));
    };

    // the user ID used for checking credential state
    char* m_userID;

    dmScript::LuaCallbackInfo* m_callback;
};

char* SiwaGetUserId();

void SiwaCheckForQueuedCallbacks();
void SiwaInitCallbackData();
void SiwaResetCallbackData();

// Queue the credential check callback to be triggered next update call in the main thread.
void SiwaQueueCredentialCallback(char* userID, SiwaCredentialState state);
// Queue the sign in authorization callback to be triggered next update call in the main thread, when authorization succeeds.
void SiwaQueueAuthSuccessCallback(const char* identityToken, const char* userID, const char* email, const char* firstName, const char* familyName, int userStatus);
// Queue the sign in authorization callback to be triggered next update call in the main thread, when authorization fails.
void SiwaQueueAuthFailureCallback(const char* message);

void SiwaRunCallback();

void SiwaSetupCallback(lua_State* L, int index);

void SiwaCleanupCallback();

// Trigged by a call from lua to check if sign in with apple is supported on this device.
bool SiwaIsAvailable();

// Triggered by a call from lua to start the sign in with apple flow
// expects the callback to be a reference number to the lua registry
// expects the context to be reference number to the lua registry
void SiwaAuthenticateWithApple();

// Triggered by a call from lua to check if a provided apple id grants this app permission to use that id.
// expects the callback to be a reference number to the lua registry
// expects the context to be reference number to the lua registry
void SiwaCheckStatusOfAppleID();

#endif
