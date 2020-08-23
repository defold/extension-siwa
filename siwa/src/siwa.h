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

// https://developer.apple.com/documentation/authenticationservices/asauthorizationappleidprovidercredentialstate/asauthorizationappleidprovidercredentialauthorized?language=objc
enum SiwaCredentialState
{
	STATE_UNKNOWN = 0,
	STATE_AUTHORIZED = 1,
	STATE_REVOKED = 2,
	STATE_NOT_FOUND = 3
};

// https://developer.apple.com/documentation/authenticationservices/asuserdetectionstatus?language=objc
enum SiwaUserDetectionStatus
{
	STATUS_UNSUPPORTED = 0,
	STATUS_LIKELY_REAL = 1,
	STATUS_UNKNOWN = 2
};

struct SiwaCallbackData
{
	SiwaCallbackData()
	{
		memset(this, 0, sizeof(*this));
	};

	SiwaCallbackCmd m_cmd;
	SiwaCredentialState m_state;
	SiwaUserDetectionStatus m_userStatus;

	char* m_identityToken;
	char* m_userID;
	char* m_email;
	char* m_firstName;
	char* m_familyName;

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

char* Siwa_GetUserId();

void Siwa_CheckForQueuedCallbacks();
void Siwa_InitCallbackData();
void Siwa_ResetCallbackData();

// Queue the credential check callback to be triggered next update call in the main thread.
void Siwa_QueueCredentialCallback(const char* userID, const SiwaCredentialState state);
// Queue the sign in authorization callback to be triggered next update call in the main thread, when authorization succeeds.
void Siwa_QueueAuthSuccessCallback(const char* identityToken, const char* userID, const char* email, const char* firstName, const char* familyName, const SiwaUserDetectionStatus userStatus);
// Queue the sign in authorization callback to be triggered next update call in the main thread, when authorization fails.
void Siwa_QueueAuthFailureCallback(const char* message);

void Siwa_TriggerCallback();
void Siwa_SetupCallback(lua_State* L, int index);
void Siwa_CleanupCallback();

// Trigged by a call from lua to check if sign in with apple is supported on this device.
bool Siwa_PlatformIsSupported();

// Triggered by a call from lua to start the sign in with apple flow
// expects the callback to be a reference number to the lua registry
// expects the context to be reference number to the lua registry
void Siwa_PlatformAuthenticateWithApple();

// Triggered by a call from lua to check if a provided apple id grants this app permission to use that id.
// expects the callback to be a reference number to the lua registry
// expects the context to be reference number to the lua registry
void Siwa_PlatformGetCredentialState();

#endif
