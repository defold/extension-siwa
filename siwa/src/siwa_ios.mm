#if defined(DM_PLATFORM_IOS)

#include "siwa_ios.h"

#include "siwa_callbacks.h"

#include <AuthenticationServices/AuthenticationServices.h>

#include <dmsdk/dlib/log.h>
#include <dmsdk/dlib/mutex.h>
#include <dmsdk/script/script.h>
#include <dmsdk/sdk.h>

#include <stdlib.h>
#include <string.h>

// Data used to ensure we only have 1 request in progress with Apples servers at a time.
// Access should be restricted behind mutex protection as the callbacks from apple can
// be triggered in arbitrary contexts.
// This data is also used to hold information passed from lua until the callback comes
// back from Apple, so that we may pass it back to lua to identify the request we are
// getting a callback for.
struct SiwaData
{
    SiwaData() {
        memset(this, 0, sizeof(*this));
        m_userID = nullptr;
        m_Callback = LUA_NOREF;
        m_Self = LUA_NOREF;

        m_waitingOnCallback = false;
    }

    // the user ID used for checking credential state
    char* m_userID;

    // references the lua state, script instance and function callback
    // to be triggered when the request to apple is complete.
    int m_Callback;
    int m_Self;
    lua_State* m_MainThread;

    // used to prevent multiple requests to apple being in progress at once.
    bool m_waitingOnCallback;
};

static SiwaData g_SiwaData;
static dmMutex::HMutex g_siwaMutex;

static void CleanupSiwaData() {
    g_SiwaData.m_waitingOnCallback = false;
    g_SiwaData.m_MainThread = nullptr;
    g_SiwaData.m_Self = LUA_NOREF;
    g_SiwaData.m_Callback = LUA_NOREF;
}

// The sign in with Apple flow expects us to have a delegate to which it can both pass data from the sign in flow
// but also how to figure out in which UI context it should display the native login UI.
// This class is that delegate.
// It also owns the provider that is both used for the sign in flow, as well as for credential state checking.
API_AVAILABLE(ios(13.0))
@interface SiwaManager : NSObject <ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding>
@property (nonatomic, strong) ASAuthorizationAppleIDProvider *m_idProvider;
@end

@implementation SiwaManager

- (instancetype) init
{
    self = [super init];
    if (self)
    {
        self.m_idProvider = [[ASAuthorizationAppleIDProvider alloc] init];
    }
    return self;
}

// Check if the user id provided to use from lua still grants our app permission
// to use it for sign in. User's can revoke app's permissions to use the id for sign in
// at any time, so we need to be able to monitor this.
// The possible results are revoked(0), authorized(1), and unknown(2).
// In practice, we have recieved unknown when revoking permission to this test app
// so we should treat both revoked and unknown as unauthorized.
- (void) checkCredentialStatus
{
    char* user_id = nullptr;
    {
        DM_MUTEX_SCOPED_LOCK(g_siwaMutex)
        user_id = g_SiwaData.m_userID;
    }

    if(user_id == nullptr)
    {
        dmLogInfo("provided user id was NULL!");
        return;
    }

    NSString* user_id_string = [[NSString alloc] initWithUTF8String:user_id];

    [self.m_idProvider getCredentialStateForUserID: user_id_string
            completion: ^(ASAuthorizationAppleIDProviderCredentialState credentialState, NSError* error) {

        // TODO: docs provide no information about what type of errors we can expect:
        // https://developer.apple.com/documentation/authenticationservices/asauthorizationappleidprovider/3175423-getcredentialstateforuserid?language=objc
        if (error) {
            dmLogError("getCredentialStateForUserID completed with error");
        }

        switch(credentialState) {
        case ASAuthorizationAppleIDProviderCredentialAuthorized:
             dmLogInfo("credential state: ASAuthorizationAppleIDProviderCredentialAuthorized");
            break;
        case ASAuthorizationAppleIDProviderCredentialRevoked:
            dmLogInfo("credential state: ASAuthorizationAppleIDProviderCredentialRevoked");
            break;
        case ASAuthorizationAppleIDProviderCredentialNotFound:
            dmLogInfo("credential state: ASAuthorizationAppleIDProviderCredentialNotFound");
            break;
        default:
            dmLogInfo("credential state: unknown!!!");
            break;
        }

        DM_MUTEX_SCOPED_LOCK(g_siwaMutex)
        dmSiwa::QueueCredentialCallback(g_SiwaData.m_MainThread, g_SiwaData.m_Self, g_SiwaData.m_Callback, g_SiwaData.m_userID, credentialState);

        // now that the callback is queued, we can clean up the held data.
        free(g_SiwaData.m_userID);
        g_SiwaData.m_userID = nullptr;
        CleanupSiwaData();
    }];
}

// triggers the sign in with Apple native ui flow to begin.
- (void) loginWithUI
{
    ASAuthorizationAppleIDRequest* request = [self.m_idProvider createRequest];
    request.requestedScopes = @[ASAuthorizationScopeFullName, ASAuthorizationScopeEmail];

    ASAuthorizationController* authController = [[ASAuthorizationController alloc] initWithAuthorizationRequests:@[request]];
    authController.presentationContextProvider = self;
    authController.delegate = self;

    [authController performRequests];
}

// the Auth controller needs to specify where to display the native login.
// this is the function our SiwaManager delegate has to implement to provide that information.
- (ASPresentationAnchor)presentationAnchorForAuthorizationController:(ASAuthorizationController *)controller {
    UIWindow *window = [UIApplication sharedApplication].keyWindow;
    return window;
}

// the Auth controller callback for getting a response back from apple for a sign in
- (void)authorizationController:(ASAuthorizationController *)controller
didCompleteWithAuthorization:(ASAuthorization *)authorization {
    if ([authorization.credential class] == [ASAuthorizationAppleIDCredential class]) {
        ASAuthorizationAppleIDCredential* appleIdCredential = ((ASAuthorizationAppleIDCredential*) authorization.credential);

        ///////////////////////////////////////////////
        // Pull data out of the auth and translate to cpp types
        ///////////////////////////////////////////////
        const char* appleUserId = [appleIdCredential.user UTF8String];
        const char* email = [appleIdCredential.email UTF8String];
        const char* givenName = [appleIdCredential.fullName.givenName UTF8String];
        const char* familyName = [appleIdCredential.fullName.familyName UTF8String];
        const int userDetectionStatus = (int) appleIdCredential.realUserStatus;
        NSString* tokenString = [[NSString alloc] initWithData:appleIdCredential.identityToken encoding:NSUTF8StringEncoding];
        const char* identityToken = [tokenString UTF8String];
        ///////////////////////////////////////////////

        DM_MUTEX_SCOPED_LOCK(g_siwaMutex)
        dmSiwa::QueueAuthSuccessCallback(g_SiwaData.m_MainThread, g_SiwaData.m_Self, g_SiwaData.m_Callback, identityToken, appleUserId, email, givenName, familyName, userDetectionStatus);
        CleanupSiwaData();
    }
    else
    {
        DM_MUTEX_SCOPED_LOCK(g_siwaMutex)
        dmSiwa::QueueAuthFailureCallback(g_SiwaData.m_MainThread, g_SiwaData.m_Self, g_SiwaData.m_Callback, "authorization failed!");
        CleanupSiwaData();
    }
}

// The Auth controller callback for getting an error during authorization
- (void)authorizationController:(ASAuthorizationController *)controller
didCompleteWithError:(NSError *)error {
    DM_MUTEX_SCOPED_LOCK(g_siwaMutex)
    dmSiwa::QueueAuthFailureCallback(g_SiwaData.m_MainThread, g_SiwaData.m_Self, g_SiwaData.m_Callback, "authorization error!");
    CleanupSiwaData();
}

@end

namespace siwa_code {
namespace platform {
    
    void AppInitialize() {
        g_siwaMutex = dmMutex::New();
        dmSiwa::InitCallbacks();
    }

    void AppFinalize() {
    }

    void Initialize() {
    }

    void Update() {
        dmSiwa::CheckForQueuedCallbacks();
    }

    void Finalize() {
    }

    // Checks if Siwa is supported on this device by seeing if the main
    // class involved in all the siwa requests we use exists.
    // Used by the native code side of this module.
    static bool IsSiwaAvailable()
    {
        return ([ASAuthorizationAppleIDProvider class] != nil);
    }

    // Checks if Siwa is supported on this device.
    // Exposed to lua.
    int IsSiwaSupported(lua_State* L)
    {
        DM_LUA_STACK_CHECK(L, 1);

        if(IsSiwaAvailable())
        {
            lua_pushboolean(L, 1);
        }
        else
        {
            lua_pushboolean(L, 0);
        }

        return 1;
    }

    //Cleans up callback data so that its fresh for the next callback.
    //!!! Not Thread safe on g_siwaData !!!
    //Make sure whatever is calling this wraps a mutex around this call
    static void CallbackSetup(lua_State* L)
    {
        if (g_SiwaData.m_Callback != LUA_NOREF) {
            dmLogError("Unexpected callback set");

            dmScript::Unref(L, LUA_REGISTRYINDEX, g_SiwaData.m_Callback);
            dmScript::Unref(L, LUA_REGISTRYINDEX, g_SiwaData.m_Self);
            g_SiwaData.m_Callback = LUA_NOREF;
            g_SiwaData.m_Self = LUA_NOREF;
        }

        if(g_SiwaData.m_userID != nullptr){
            free(g_SiwaData.m_userID);
            g_SiwaData.m_userID = nullptr;
        }
    }

    API_AVAILABLE(ios(13.0))
    static SiwaManager* g_siwaManager = nil;

    API_AVAILABLE(ios(13.0))
    static SiwaManager* GetSiwaManager()
    {
        if(g_siwaManager == nil)
        {
            g_siwaManager = [[SiwaManager alloc] init];
        }

        return g_siwaManager;
    }

    API_AVAILABLE(ios(13.0))
    // Kicks off the request to check the credential state of a provided user id.
    void DoCheckStatus(lua_State* L, char* userID, int callback, int context, lua_State* thread) {
        {
            DM_MUTEX_SCOPED_LOCK(g_siwaMutex)
            if(g_SiwaData.m_waitingOnCallback)
            {
                dmLogError("ERROR: Callback already in progress, abort");
                return;
            }

            CallbackSetup(L);

            g_SiwaData.m_userID = userID; //taking ownership
            g_SiwaData.m_Callback = callback;
            g_SiwaData.m_Self = context;
            g_SiwaData.m_MainThread = thread;

            g_SiwaData.m_waitingOnCallback = true;
        }

        SiwaManager *siwaMan = GetSiwaManager();
        [siwaMan checkCredentialStatus];
        return;
    }

    API_AVAILABLE(ios(13.0))
    // Kicks off the sign in with apple flow.
    void DoAuthentication(lua_State* L, int callback, int context, lua_State* thread){
        {
            DM_MUTEX_SCOPED_LOCK(g_siwaMutex)
            if(g_SiwaData.m_waitingOnCallback)
            {
                dmLogError("ERROR: Callback already in progress, abort");
                return;
            }

            CallbackSetup(L);

            g_SiwaData.m_Callback = callback;
            g_SiwaData.m_Self = context;
            g_SiwaData.m_MainThread = thread;

            g_SiwaData.m_waitingOnCallback = true;
        }

        SiwaManager *siwaMan = GetSiwaManager();
        [siwaMan loginWithUI];
    }

    int CheckStatusOfAppleID(lua_State* L, char* userID, int callback, int context, lua_State* thread) {
        DM_LUA_STACK_CHECK(L, 0);

        if(IsSiwaAvailable())
        {
            DoCheckStatus(L, userID, callback, context, thread);
        }

        return 0;
    }

    int AuthenticateWithApple(lua_State* L, int callback, int context, lua_State* thread) {
        DM_LUA_STACK_CHECK(L, 0);

        if(IsSiwaAvailable())
        {
            DoAuthentication(L, callback, context, thread);
        }

        return 0;
    }

} // namespace
} // namespace

#endif
