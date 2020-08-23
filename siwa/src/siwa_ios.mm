#if defined(DM_PLATFORM_IOS)

#include "siwa.h"

#include <AuthenticationServices/AuthenticationServices.h>

#include <dmsdk/sdk.h>

#include <stdlib.h>
#include <string.h>


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
    char* userId = SiwaGetUserId();
    NSString* user_id_string = [[NSString alloc] initWithUTF8String:userId];

    [self.m_idProvider getCredentialStateForUserID: user_id_string
            completion: ^(ASAuthorizationAppleIDProviderCredentialState credentialState, NSError* error) {

        // TODO: docs provide no information about what type of errors we can expect:
        // https://developer.apple.com/documentation/authenticationservices/asauthorizationappleidprovider/3175423-getcredentialstateforuserid?language=objc
        if (error) {
            dmLogError("getCredentialStateForUserID completed with error");
        }

        SiwaCredentialState state = STATE_UNKNOWN;
        switch(credentialState) {
        case ASAuthorizationAppleIDProviderCredentialAuthorized:
            dmLogInfo("credential state: ASAuthorizationAppleIDProviderCredentialAuthorized");
            state = STATE_AUTHORIZED;
            break;
        case ASAuthorizationAppleIDProviderCredentialRevoked:
            dmLogInfo("credential state: ASAuthorizationAppleIDProviderCredentialRevoked");
            state = STATE_REVOKED;
            break;
        case ASAuthorizationAppleIDProviderCredentialNotFound:
            dmLogInfo("credential state: ASAuthorizationAppleIDProviderCredentialNotFound");
            state = STATE_NOT_FOUND;
            break;
        default:
            dmLogInfo("credential state: unknown!!!");
            break;
        }

        SiwaQueueCredentialCallback(userId, state);
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

        const char* appleUserId = [appleIdCredential.user UTF8String];
        const char* email = [appleIdCredential.email UTF8String];
        const char* givenName = [appleIdCredential.fullName.givenName UTF8String];
        const char* familyName = [appleIdCredential.fullName.familyName UTF8String];
        const int userDetectionStatus = (int) appleIdCredential.realUserStatus;
        NSString* tokenString = [[NSString alloc] initWithData:appleIdCredential.identityToken encoding:NSUTF8StringEncoding];
        const char* identityToken = [tokenString UTF8String];

        SiwaQueueAuthSuccessCallback(identityToken, appleUserId, email, givenName, familyName, userDetectionStatus);
    }
    else
    {
        SiwaQueueAuthFailureCallback("authorization failed!");
    }
}

// The Auth controller callback for getting an error during authorization
- (void)authorizationController:(ASAuthorizationController *)controller
didCompleteWithError:(NSError *)error {
    SiwaQueueAuthFailureCallback("authorization error!");
}

@end


// Checks if Siwa is supported on this device by seeing if the main
// class involved in all the siwa requests we use exists.
bool SiwaIsAvailable()
{
    return ([ASAuthorizationAppleIDProvider class] != nil);
}

API_AVAILABLE(ios(13.0))
static SiwaManager* g_SiwaManager = nil;

API_AVAILABLE(ios(13.0))
SiwaManager* GetSiwaManager()
{
    if(g_SiwaManager == nil)
    {
        g_SiwaManager = [[SiwaManager alloc] init];
    }

    return g_SiwaManager;
}

API_AVAILABLE(ios(13.0))
// Kicks off the request to check the credential state of a provided user id.
void SiwaDoCheckStatus() {
    SiwaManager *siwaMan = GetSiwaManager();
    [siwaMan checkCredentialStatus];
    return;
}

API_AVAILABLE(ios(13.0))
// Kicks off the sign in with apple flow.
void SiwaDoAuthentication() {
    SiwaManager *siwaMan = GetSiwaManager();
    [siwaMan loginWithUI];
}

void SiwaCheckStatusOfAppleID() {
    SiwaDoCheckStatus();
}

void SiwaAuthenticateWithApple() {
    SiwaDoAuthentication();
}

#endif
