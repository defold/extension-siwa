#pragma once

// A collection of helper structs and functions for running lua callbacks provided
// when the module methods were initially called. The sign in with apple sign in flow
// and credential state checking

struct lua_State;

namespace dmSiwa {

	// The state of our own callbacks:
	// IDLE: default state, available to trigger a callbak
	// QUEUED: We've received a callback from able, and have queued our own associated callback
	//		   to run on the main thread.
	// RUNNING: Our callback is currently running on the main thread.
	enum CallbackState{
		IDLE,
		QUEUED,
		RUNNING
	};

	// Holds data recevied from the callback for checking credential state
	// so that we can access it on the main thread, since the Apple callback
	// can be triggered in any arbitrary thread context.
	struct CredentialCallbackData{
		public:

		// Standard data needed to trigger a callback in lua
		lua_State* m_L;
		int m_self;
		int m_callback;

		// Data to be passed to lua
		char* m_userID;
		int m_status;

		// used for determining when to trigger a callback
		CallbackState m_cbState;
	};

	// Holds data recevied from the callback for the Apple sign in flow
	// so that we can access it on the main thread, since the Apple callback
	// can be triggered in any arbitrary thread context.
	struct AuthCallbackData{
		public:

		// Standard data needed to trigger a callback in lua
		lua_State* m_L;
		int m_self;
		int m_callback;

		// Data to be passed to lua on a successful authorization
		char* m_identityToken;
		char* m_userID;
		char* m_email;
		char* m_firstName;
		char* m_familyName;
		int m_userStatus;

		// Data to be passed to lua on a failed authorization
		char* m_message;

		// used for determining when to trigger a callback
		CallbackState m_cbState;
		bool m_success;
	};

	// Sets up data and mutexes to handle capturing data from Apple callbacks
	// and running our own associated callbacks on the main thread.
	void InitCallbacks();

	// Check if an callbacks have been queued since the last updated on the main
	// thread, and if so, trigger the callback.
	void CheckForQueuedCallbacks();

	// Common setup to run each time we want to trigger a callback in lua.
	bool RunCallbackSetup(lua_State* L, int _self, int _callback);

	// One-time setup for credential checking callbacks.
	void InitCredentialCallbackData();
	// Setup to be run as the credential checking callback is set to idle
	void ResetCredentialCallbackData();
	// Queue the credential check callback to be triggered next update call in the main thread.
	void QueueCredentialCallback(lua_State* L, int _self, int _callback, char* userID, int status);
	// Check if the credential check callback was queued to run in the next update call in the main thread.
	void CheckForCredentialCallback();
	// Setup the credential check callback to be called in lua on the main thread, and trigger it
	void RunCredentialCallback();

	// One-time setup for sign in authorization callbacks.
	void InitAuthCallbackData();
	// Setup to be run as the sign in authorizationcallback is set to idle
	void ResetAuthCallbackData();
	// Queue the sign in authorization callback to be triggered next update call in the main thread, when authorization succeeds.
	void QueueAuthSuccessCallback(lua_State* L, int _self, int _callback, const char* identityToken, const char* userID, const char* email, const char* firstName, const char* familyName, int userStatus);
	// Queue the sign in authorization callback to be triggered next update call in the main thread, when authorization fails.
	void QueueAuthFailureCallback(lua_State* L, int _self, int _callback, const char* message);
	// Check if the sign in authorization callback was queued to run in the next update call in the main thread.
	void CheckForAuthCallback();
	// Setup the sign in authorization callback for when authorization succeeds to be called in lua on the main thread, and trigger it
	void RunAuthSuccessCallback();
	// Setup the sign in authorization callback for when authorization fails to be called in lua on the main thread, and trigger it
	void RunAuthFailureCallback();
}
