﻿using ServiceStack.Auth;
using ServiceStack.Configuration;
using ServiceStack.Text;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Net;
using System.Text;

// This is still a work in progress...

namespace ServiceStack.Authentication.Aad
{
    /// <summary>
    /// Azure Active Directory Auth Provider
    /// See: https://msdn.microsoft.com/en-us/library/azure/dn645542.aspx
    /// </summary>
    public class AadAuthProvider : OAuthProvider
    {
        public const string Name = "aad";
        public static string Realm = "https://login.microsoftonline.com/";

        // TODO: Update AuthorizeUrl and AccessTokenUrl when TenantId changed
        public string TenantId { get; set; }

        public string ClientId
        {
            get { return ConsumerKey; }
            set { ConsumerKey = value; }
        }

        public string ClientSecret {
            get { return ConsumerSecret; }
            set { ConsumerSecret = value; }
        }

        public string[] Scopes { get; set; }


        public AadAuthProvider()
            : this(new AppSettings())
        {
        }

        public AadAuthProvider(IAppSettings appSettings)
            : base(appSettings, Realm, Name, "ClientId", "ClientSecret")
        {
            // To get the authorization code, the web browser (or an embedded web browser 
            // control) navigates to a tenant-specific or common (tenant-independent) endpoint.
            TenantId = appSettings.Get("oauth.{0}.TenantId".Fmt(Provider), "common");
            var baseAuthUrl = Realm + TenantId + "/oauth2/";
            AuthorizeUrl = appSettings.Get("oauth.{0}.AuthorizeUrl".Fmt(Provider), baseAuthUrl + "authorize");
            AccessTokenUrl = appSettings.Get("oauth.{0}.AccessTokenUrl".Fmt(Provider), baseAuthUrl + "token");
            // TODO: Note that RequestTokenUrl is not used... 
            Scopes = appSettings.Get("oauth.aad.Scopes", new[] { "user_impersonation" });
        }

        public override object Authenticate(IServiceBase authService, IAuthSession session, Authenticate request)
        {
            // TODO: WARN: Property 'code' does not exist on type 'ServiceStack.Authenticate'
            // TODO: WARN: Property 'session_state' does not exist on type 'ServiceStack.Authenticate'

            var tokens = Init(authService, ref session, request);
            var httpRequest = authService.Request;

            // 1. The client application starts the flow by redirecting the user agent 
            //    to the Azure AD authorization endpoint. The user authenticates and 
            //    consents, if consent is required.

            //https://developer.github.com/v3/oauth/#common-errors-for-the-authorization-request
            var error = httpRequest.QueryString["error"]
                        ?? httpRequest.QueryString["error_uri"]
                        ?? httpRequest.QueryString["error_description"];

            var hasError = !error.IsNullOrEmpty();
            if (hasError)
            {
                Log.Error("AAD error callback. {0}".Fmt(httpRequest.QueryString["error_description"].UrlDecode()));
                return authService.Redirect(FailedRedirectUrlFilter(this, session.ReferrerUrl.SetParam("f", error)));
            }

            // STEP 1: Request Code
            var code = httpRequest.QueryString["code"];
            var isPreAuthCallback = !code.IsNullOrEmpty();
            if (!isPreAuthCallback)
            {
                string preAuthUrl = AuthorizeUrl + "?response_type=code&client_id={0}&redirect_uri={1}&scope={2}&state={3}"
                    .Fmt(ClientId, CallbackUrl.UrlEncode(), Scopes.Join(","), Guid.NewGuid().ToString("N"));
                authService.SaveSession(session, SessionExpiry);
                return authService.Redirect(PreAuthUrlFilter(this, preAuthUrl));
            }

            // 2. The Azure AD authorization endpoint redirects the user agent back 
            //    to the client application with an authorization code. The user 
            //    agent returns authorization code to the client application’s redirect URI.
            // 3. The client application requests an access token from the 
            //    Azure AD token issuance endpoint. It presents the authorization code 
            //    to prove that the user has consented.

            // STEP 2: Request Token
            var formData = "client_id={0}&redirect_uri={1}&client_secret={2}&code={3}&grant_type=authorization_code&resource=00000002-0000-0000-c000-000000000000"
                .Fmt(ClientId, CallbackUrl.UrlEncode(), ClientSecret.UrlEncode(), code);
            try
            {
                // Endpoint only accepts posts requests
                var contents = AccessTokenUrl.PostToUrl(formData);

                // 4. The Azure AD token issuance endpoint returns an access token 
                //    and a refresh token. The refresh token can be used to request 
                //    additional access tokens.

                // Response is JSON
                var authInfo = JsonObject.Parse(contents);
                var accessTokenError = authInfo["error"]
                                       ?? authInfo["error_uri"]
                                       ?? authInfo["error_description"];
                if (!accessTokenError.IsNullOrEmpty())
                {
                    Log.Error("access_token error callback. {0}".Fmt(authInfo.ToString()));
                    return authService.Redirect(FailedRedirectUrlFilter(this, session.ReferrerUrl.SetParam("f", "AccessTokenFailed")));
                }
                // TODO: Validate matching `state`
                tokens.AccessTokenSecret = authInfo["access_token"];
                session.IsAuthenticated = true;
                return OnAuthenticated(authService, session, tokens, authInfo.ToDictionary())
                       ?? authService.Redirect(SuccessRedirectUrlFilter(this, session.ReferrerUrl.SetParam("s", "1"))); //Haz Access!
            }
            catch (WebException webException)
            {
                Log.Error("Auth Failure", webException);
                var response = ((HttpWebResponse) webException.Response);
                var responseText = Encoding.UTF8.GetString(
                    response.GetResponseStream().ReadFully());
                Log.Error(responseText);
                // TODO: Error response is JSON. Can get error code and description
                var statusCode = response.StatusCode;
                if (statusCode == HttpStatusCode.BadRequest)
                {
                    return authService.Redirect(FailedRedirectUrlFilter(this, session.ReferrerUrl.SetParam("f", "AccessTokenFailed")));
                }
            }
            return authService.Redirect(FailedRedirectUrlFilter(this, session.ReferrerUrl.SetParam("f", "Unknown")));
        }

        protected override void LoadUserAuthInfo(AuthUserSession userSession, IAuthTokens tokens, Dictionary<string, string> authInfo)
        {
            try
            {
                // The id_token is a JWT token. See http://jwt.io
                var jwt = new JwtSecurityToken(authInfo["id_token"]);
                // TODO: Validate JWT is signed in expected way
                var p = jwt.Payload;
                tokens.UserId = (string)p["oid"];
                tokens.UserName = (string) p["upn"];
                tokens.DisplayName = (string) p["name"];
                // TODO: Get Email address
                //tokens.Email = (string) p["email"];
                //tokens.Company = obj.Get("company");
                //tokens.Country = obj.Get("country");
                // TODO: Save other payload info
                //if (SaveExtendedUserInfo)
                //{
                //    obj.Each(x => authInfo[x.Key] = x.Value);
                //}
            }
            catch (Exception ex)
            {
                Log.Error("Could not retrieve user info", ex);
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
    }
}
