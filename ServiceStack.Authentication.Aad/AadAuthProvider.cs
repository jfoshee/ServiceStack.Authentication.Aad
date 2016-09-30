using ServiceStack.Auth;
using ServiceStack.Configuration;
using ServiceStack.Text;
using ServiceStack.Web;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IdentityModel.Tokens;
using System.IO;
using System.Net;
using System.Reflection;
using System.Text;

namespace ServiceStack.Authentication.Aad
{
    /// <summary>
    /// Azure Active Directory (AAD) Auth Provider
    /// </summary>
    /// <remarks>
    /// You must provide the `ClientId` and `ClientSecret`.
    /// They can be provided to the constructor, by setting the properties,
    /// or in the app.config appsettings under the following keys: 
    /// `oauth.aad.ClientId` and `oauth.aad.ClientSecret`
    /// 
    /// You may also provide the `TenantId` of your AAD resource.
    /// The Tenant ID can be found in the oauth2 endpoint as shown:
    /// https://login.microsoftonline.com/{TenantId}/oauth2/token
    /// If no Tenant ID is provided the `common` tenant will be used.
    /// 
    /// The `CallbackUrl` will default
    /// to the /auth/aad path, but it can be configured explicitly. In either
    /// case it must match what has been configured on Azure as a "REPLY URL".
    /// 
    /// The following properties are not used. If any are configured a warning
    /// will be logged. This can be disabled with `LogConfigurationWarnings`.
    /// - `RedirectUrl`
    /// - `RequestTokenUrl`
    /// </remarks>
    /// <seealso href="https://msdn.microsoft.com/en-us/library/azure/dn645542.aspx"/>
    public class AadAuthProvider : OAuthProvider
    {
        public const string Name = "aad";
        public static string Realm = "https://login.microsoftonline.com/";

        public string BaseAuthUrl
        {
            get
            {
                var tenantId = TenantId.IsNullOrEmpty() ? "common" : TenantId;
                return Realm + tenantId + "/oauth2/";
            }
        }
        public IAppSettings AppSettings { get; private set; }

        private string _tenantId;
        public string TenantId
        {
            get { return _tenantId; }
            set
            {
                _tenantId = value;
                // To get the authorization code, the web browser (or an embedded web browser 
                // control) navigates to a tenant-specific or common (tenant-independent) endpoint.
                AuthorizeUrl = AppSettings.Get("oauth.{0}.AuthorizeUrl".Fmt(Provider), BaseAuthUrl + "authorize");
                AccessTokenUrl = AppSettings.Get("oauth.{0}.AccessTokenUrl".Fmt(Provider), BaseAuthUrl + "token");
            }
        }

        public string ClientId
        {
            get { return ConsumerKey; }
            set { ConsumerKey = value; }
        }

        public string ClientSecret {
            get { return ConsumerSecret; }
            set { ConsumerSecret = value; }
        }

        public string ResourceId { get; set; }

        public string DomainHint { get; set; }

        public string[] Scopes { get; set; }

        private string _failureRedirectPath;
        public string FailureRedirectPath
        {
            get { return _failureRedirectPath; }
            set
            {
                if (!value.StartsWith("/"))
                    throw new FormatException("FailureRedirectPath should start with '/'");
                _failureRedirectPath = value;
            }
        }

        public static bool LogConfigurationWarnings { get; set; }
        

        static AadAuthProvider()
        {
            LogConfigurationWarnings = true;
        }

        public AadAuthProvider()
            : this(new AppSettings())
        {
        }

        public AadAuthProvider(string clientId, string clientSecret)
            : this()
        {
            ClientId = clientId;
            ClientSecret = clientSecret;
        }

        public AadAuthProvider(string clientId, string clientSecret, IAppSettings appSettings)
            : this(appSettings)
        {
            ClientId = clientId;
            ClientSecret = clientSecret;
        }

        public AadAuthProvider(IAppSettings appSettings)
            : base(appSettings, Realm, Name, "ClientId", "ClientSecret")
        {
            AppSettings = appSettings;
            TenantId = AppSettings.Get<string>("oauth.{0}.TenantId".Fmt(Provider), null);
            DomainHint = AppSettings.Get<string>("oauth.{0}.DomainHint".Fmt(Provider), null);
            ResourceId = AppSettings.Get("oauth.{0}.ResourceId".Fmt(Provider), "00000002-0000-0000-c000-000000000000");
            Scopes = AppSettings.Get("oauth.{0}.Scopes", new[] { "user_impersonation" });
            FailureRedirectPath = AppSettings.Get("oauth.{0}.FailureRedirectPath".Fmt(Provider), "/");
            if (RedirectUrl != null && LogConfigurationWarnings)
                Log.Warn("{0} auth provider does not use the RedirectUrl, but one has been configured.".Fmt(Provider));
            if (RequestTokenUrl != Realm + "oauth/request_token" && LogConfigurationWarnings)
                Log.Warn("{0} auth provider does not use the RequestTokenUrl, but one has been configured.".Fmt(Provider));
        }

        protected override string GetReferrerUrl(IServiceBase authService, IAuthSession session, Authenticate request = null)
        {
            // TODO: The base implementation should check the redirect param.
            return authService.Request.GetParam("redirect") ??
                base.GetReferrerUrl(authService, session, request);
            // Note that most auth providers redirect to the referrer url upon failure.
            // This implementation throws a monkey-wrench in that because we are here
            // setting the referrer url to the secure (authentication required) resource.
            // Thus redirecting to the referrer url on auth failure causes a redirect loop.
            // Therefore this auth provider redirects to FailureRedirectPath
            // The bottom line is that the user's destination should be different between success and failure
            // and the base implementation does not naturally support that
        }

        public override object Authenticate(IServiceBase authService, IAuthSession session, Authenticate request)
        {
            // TODO: WARN: Property 'redirect' does not exist on type 'ServiceStack.Authenticate'
            // TODO: WARN: Property 'code' does not exist on type 'ServiceStack.Authenticate'
            // TODO: WARN: Property 'session_state' does not exist on type 'ServiceStack.Authenticate'
            // TODO: The base Init() should strip the query string from the request URL
            if (CallbackUrl.IsNullOrEmpty())
                CallbackUrl = new Uri(authService.Request.AbsoluteUri).GetLeftPart(UriPartial.Path);
            var tokens = Init(authService, ref session, request);
            var httpRequest = authService.Request;
            var query = httpRequest.QueryString.ToNameValueCollection();
            if (HasError(query))
                return RedirectDueToFailure(authService, session, query);

            // 1. The client application starts the flow by redirecting the user agent 
            //    to the Azure AD authorization endpoint. The user authenticates and 
            //    consents, if consent is required.

            // TODO: Can State property be added to IAuthSession to avoid this cast
            var userSession = session as AuthUserSession;
            if (userSession == null)
                throw new NotSupportedException("Concrete dependence on AuthUserSession because of State property");

            var code = query["code"];
            if (code.IsNullOrEmpty())
                return RequestCode(authService, session, userSession, tokens);

            var state = query["state"];
            if (state != userSession.State)
            {
                session.IsAuthenticated = false;
                throw new UnauthorizedAccessException("Mismatched state in code response.");
            }

            // 2. The Azure AD authorization endpoint redirects the user agent back 
            //    to the client application with an authorization code. The user 
            //    agent returns authorization code to the client application’s redirect URI.
            // 3. The client application requests an access token from the 
            //    Azure AD token issuance endpoint. It presents the authorization code 
            //    to prove that the user has consented.

            return RequestAccessToken(authService, session, code, tokens);
        }

        private object RequestCode(IServiceBase authService, IAuthSession session, AuthUserSession userSession, IAuthTokens tokens)
        {
            var state = Guid.NewGuid().ToString("N");
            userSession.State = state;
            var codeRequest = AuthorizeUrl + "?response_type=code&client_id={0}&redirect_uri={1}&scope={2}&state={3}"
                .Fmt(ClientId, CallbackUrl.UrlEncode(), Scopes.Join(","), state);
            if (!DomainHint.IsNullOrEmpty())
                codeRequest += "&domain_hint=" + DomainHint;
            if (!tokens.UserName.IsNullOrEmpty())
                codeRequest += "&login_hint=" + tokens.UserName;
            authService.SaveSession(session, SessionExpiry);
            return authService.Redirect(PreAuthUrlFilter(this, codeRequest));
        }

        private IHttpResult RequestAccessToken(IServiceBase authService, IAuthSession session, string code, IAuthTokens tokens)
        {
            try
            {
                var formData = "client_id={0}&redirect_uri={1}&client_secret={2}&code={3}&grant_type=authorization_code&resource={4}"
                    .Fmt(ClientId.UrlEncode(), CallbackUrl.UrlEncode(), ClientSecret.UrlEncode(), code, ResourceId.UrlEncode());
                // Endpoint only accepts posts requests
                var contents = AccessTokenUrl.PostToUrl(formData);

                // 4. The Azure AD token issuance endpoint returns an access token 
                //    and a refresh token. The refresh token can be used to request 
                //    additional access tokens.

                // Response is JSON
                var authInfo = JsonObject.Parse(contents);
                var authInfoNvc = authInfo.ToNameValueCollection();
                if (HasError(authInfoNvc))
                    return RedirectDueToFailure(authService, session, authInfoNvc);
                tokens.AccessTokenSecret = authInfo["access_token"];
                tokens.RefreshToken = authInfo["refresh_token"];
                return OnAuthenticated(authService, session, tokens, authInfo.ToDictionary())
                       ?? authService.Redirect(SuccessRedirectUrlFilter(this, session.ReferrerUrl.SetParam("s", "1"))); //Haz Access!
            }
            catch (WebException webException)
            {
                if (webException.Response == null)
                {
                    // This could happen e.g. due to a timeout
                    return RedirectDueToFailure(authService, session, new NameValueCollection
                    {
                        {"error", webException.GetType().ToString()},
                        {"error_description", webException.Message}
                    });
                }
                Log.Error("Auth Failure", webException);
                var response = ((HttpWebResponse) webException.Response);
                var responseText = Encoding.UTF8.GetString(
                    response.GetResponseStream().ReadFully());
                var errorInfo = JsonObject.Parse(responseText).ToNameValueCollection();
                return RedirectDueToFailure(authService, session, errorInfo);
            }
            //return RedirectDueToFailure(authService, session, new NameValueCollection());
        }

        /// <summary>
        /// Returns a redirect result to a Microsoft logout page
        /// </summary>
        public IHttpResult RedirectToMicrosoftLogout(IServiceBase authService)
        {
            // See https://msdn.microsoft.com/en-us/office/office365/howto/authentication-v2-protocols
            var request = "{0}logout?client_id={1}&post_logout_redirect_uri={2}"
                .Fmt(BaseAuthUrl, ClientId, CallbackUrl.UrlEncode());
            return authService.Redirect(LogoutUrlFilter(this, request));
        }

        public override object Logout(IServiceBase service, Authenticate request)
        {
            base.Logout(service, request);
            return RedirectToMicrosoftLogout(service);
        }

        public override IHttpResult OnAuthenticated(IServiceBase authService, IAuthSession session, IAuthTokens tokens, Dictionary<string, string> authInfo)
        {
            try
            {
                // The id_token is a JWT token. See http://jwt.io
                var jwt = new JwtSecurityToken(authInfo["id_token"]);
                var p = jwt.Payload;
                var tenantId = (string)p["tid"];
                if (!TenantId.IsNullOrEmpty() && TenantId != tenantId)
                {
                    return RedirectDueToFailure(authService, session, new NameValueCollection
                    {
                        {"error", "mismatched-tenant"},
                        {"error_description", "Mismatched Tenant ID in JWT token"}
                    });
                }
                if (!p.Aud.Contains(ClientId))
                {
                    return RedirectDueToFailure(authService, session, new NameValueCollection
                    {
                        {"error", "mismatched-client-app"},
                        {"error_description", "Mismatched Client ID in JWT token"}
                    });
                }
                if (!p.ContainsKey("oid") || !p.ContainsKey("upn"))
                {
                    FailAndLogError(session, new NameValueCollection
                    {
                        {"error", "missing-user-id"},
                        {"error_description", "Missing 'oid' or 'upn' in JWT token. " +
                                              "This may imply the user logged into the wrong account. " +
                                              "For example, the user may have logged into their Microsoft Account " +
                                              "rather than their organizational account."}
                    });
                    // Here we really need to give the user a way to sign out of their MS account
                    // If the user selected "Keep me signed in" they will effectively be stuck
                    // Because Microsoft will continue to send us the same token without prompting
                    // the user for other credentials.
                    // TODO: It would be nice to momentarily show the user a message explaining why they are being signed out
                    return RedirectToMicrosoftLogout(authService);
                }
            }
            catch (Exception ex)
            {
                Log.Error("Reading JWT token", ex);
                return RedirectDueToFailure(authService, session, new NameValueCollection
                    {
                        {"error", "bad-jwt"},
                        {"error_description", "Problem checking the JWT token"}
                    });                
            }
            return base.OnAuthenticated(authService, session, tokens, authInfo);
        }

        protected override void LoadUserAuthInfo(AuthUserSession userSession, IAuthTokens tokens, Dictionary<string, string> authInfo)
        {
            try
            {
                var jwt = new JwtSecurityToken(authInfo["id_token"]);
                var p = jwt.Payload;
                tokens.UserId = (string) p["oid"];
                tokens.UserName = (string) p["upn"];
                tokens.LastName = (string) p.GetValueOrDefault("family_name");
                tokens.FirstName = (string) p.GetValueOrDefault("given_name");
                tokens.DisplayName = (string) p.GetValueOrDefault("name") ?? tokens.FirstName + " " + tokens.LastName;
                tokens.Email = (string) p.GetValueOrDefault("email");
                tokens.RefreshTokenExpiry = jwt.ValidTo;
                if (SaveExtendedUserInfo)
                    p.Each(x => authInfo[x.Key] = x.Value.ToString());
            }
            catch (KeyNotFoundException ex)
            {
                Log.Error("Reading user auth info from JWT", ex);
                throw;
            }
            LoadUserOAuthProvider(userSession, tokens);
        }

        public override void LoadUserOAuthProvider(IAuthSession authSession, IAuthTokens tokens)
        {
            var userSession = authSession as AuthUserSession;
            if (userSession == null) return;

            userSession.UserName = tokens.UserName ?? userSession.UserName;
            userSession.DisplayName = tokens.DisplayName ?? userSession.DisplayName;
            userSession.Company = tokens.Company ?? userSession.Company;
            userSession.Country = tokens.Country ?? userSession.Country;
            userSession.PrimaryEmail = tokens.Email ?? userSession.PrimaryEmail ?? userSession.Email;
            userSession.Email = tokens.Email ?? userSession.PrimaryEmail ?? userSession.Email;
        }

        private static bool HasError(NameValueCollection info)
        {
            return !(info["error"] ?? info["error_uri"] ?? info["error_description"]).IsNullOrEmpty();
        }

        protected IHttpResult RedirectDueToFailure(IServiceBase authService, IAuthSession session, NameValueCollection errorInfo)
        {
            FailAndLogError(session, errorInfo);
            var baseUrl = authService.Request.GetBaseUrl();
            var destination = !FailureRedirectPath.IsNullOrEmpty() ? 
                baseUrl + FailureRedirectPath :
                session.ReferrerUrl ?? baseUrl;
            var fparam = errorInfo["error"] ?? "Unknown";
            return authService.Redirect(FailedRedirectUrlFilter(this, destination.SetParam("f", fparam)));
        }

        private void FailAndLogError(IAuthSession session, NameValueCollection errorInfo)
        {
            session.IsAuthenticated = false;
            if (HasError(errorInfo))
                Log.Error("{0} OAuth2 Error: '{1}' : \"{2}\" <{3}>".Fmt(
                    Provider,
                    errorInfo["error"],
                    errorInfo["error_description"].UrlDecode(),
                    errorInfo["error_uri"].UrlDecode()));
            else
                Log.Error("Unknown {0} OAuth2 Error".Fmt("Provider"));
        }
    }
}
