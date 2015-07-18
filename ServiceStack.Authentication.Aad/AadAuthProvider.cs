using ServiceStack.Auth;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Net;
using System.Text;
using ServiceStack.Configuration;
using ServiceStack.Text;

// This is a big work in progress...

namespace ServiceStack.Authentication.Aad
{
    /// <summary>
    /// Azure Active Directory Auth Provider
    /// </summary>
    public class AadAuthProvider : OAuthProvider
    {
        public const string Name = "aad";
        public static string Realm = "https://login.microsoftonline.com/";        
        public static string PreAuthUrl = "https://login.microsoftonline.com/{0}/oauth2/authorize";

        public string TenantId { get; set; }

        public string ClientId { get; set; }

        public string ClientSecret { get; set; }

        public string[] Scopes { get; set; }


        public AadAuthProvider()
            : this(new AppSettings())
        {
        }

        public AadAuthProvider(IAppSettings appSettings)
            : base(appSettings, Realm, Name, "ClientId", "ClientSecret")
        {
            ClientId = appSettings.GetString("oauth.aad.ClientId");
            ClientSecret = appSettings.GetString("oauth.aad.ClientSecret");
            TenantId = appSettings.GetString("oauth.aad.TenantId");
            AccessTokenUrl = Realm + TenantId + "/oauth2/token";
            Scopes = appSettings.Get("oauth.aad.Scopes", new[] { "user_impersonation" });
        }

        public override object Authenticate(IServiceBase authService, IAuthSession session, Authenticate request)
        {

            var tokens = Init(authService, ref session, request);
            var httpRequest = authService.Request;

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

            var code = httpRequest.QueryString["code"];
            var isPreAuthCallback = !code.IsNullOrEmpty();
            if (!isPreAuthCallback)
            {
                string preAuthUrl = PreAuthUrl.Fmt(TenantId) + "?client_id={0}&redirect_uri={1}&scope={2}&state={3}&response_type=code"
                    .Fmt(ClientId, CallbackUrl.UrlEncode(), Scopes.Join(","), Guid.NewGuid().ToString("N"));

                authService.SaveSession(session, SessionExpiry);
                return authService.Redirect(PreAuthUrlFilter(this, preAuthUrl));
            }


            string accessTokenUrl = AccessTokenUrl + "?client_id={0}&redirect_uri={1}&client_secret={2}&code={3}"
                .Fmt(ClientId, CallbackUrl.UrlEncode(), ClientSecret, code);
            var formData = "client_id={0}&redirect_uri={1}&client_secret={2}&code={3}&grant_type=authorization_code&resource=00000002-0000-0000-c000-000000000000"
                .Fmt(ClientId, CallbackUrl.UrlEncode(), ClientSecret.UrlEncode(), code);

            try
            {
                // Endpoint only accepts posts requests
                var contents = AccessTokenUrl.PostToUrl(formData);
                //    , "*/*", null, response =>
                //{
                //    response.PrintDump();
                //});
                //    new
                //{
                //    client_id = ClientId.UrlEncode(),
                //    client_secret = ClientSecret.UrlEncode(),
                //    code = code,
                //    grant_type = "authorization_code",
                //    redirect_uri = CallbackUrl.UrlEncode(),
                //    resource = "00000002-0000-0000-c000-000000000000" // [Optional] The App ID URI of the web API (secured resource).
                //});

                //var contents = AccessTokenUrlFilter(this, accessTokenUrl).PostToUrl(null);

                // Response is JSON
                var authInfo = JsonObject.Parse(contents);
                //var authInfo = HttpUtility.ParseQueryString(contents);

                //GitHub does not throw exception, but just return error with descriptions
                //https://developer.github.com/v3/oauth/#common-errors-for-the-access-token-request
                var accessTokenError = authInfo["error"]
                                       ?? authInfo["error_uri"]
                                       ?? authInfo["error_description"];

                if (!accessTokenError.IsNullOrEmpty())
                {
                    Log.Error("GitHub access_token error callback. {0}".Fmt(authInfo.ToString()));
                    return authService.Redirect(FailedRedirectUrlFilter(this, session.ReferrerUrl.SetParam("f", "AccessTokenFailed")));
                }
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
                //just in case GitHub will start throwing exceptions 
                var statusCode = ((HttpWebResponse)webException.Response).StatusCode;
                if (statusCode == HttpStatusCode.BadRequest)
                {
                    return authService.Redirect(FailedRedirectUrlFilter(this, session.ReferrerUrl.SetParam("f", "AccessTokenFailed")));
                }
            }
            return authService.Redirect(FailedRedirectUrlFilter(this, session.ReferrerUrl.SetParam("f", "Unknown")));

        }

        /// <summary>
        ///   Calling to Github API without defined Useragent throws
        ///   exception "The server committed a protocol violation. Section=ResponseStatusLine"
        /// </summary>
        protected virtual void UserRequestFilter(HttpWebRequest request)
        {
            request.UserAgent = ServiceClientBase.DefaultUserAgent;
        }

        protected override void LoadUserAuthInfo(AuthUserSession userSession, IAuthTokens tokens, Dictionary<string, string> authInfo)
        {
            try
            {
                // TODO: Figure out user info URL
                //var json = "https://login.microsoftonline.com/fe23e5c3-19be-467d-8a25-4bc12004ee65/user?access_token={0}".Fmt(tokens.AccessTokenSecret)
                //    .GetStringFromUrl("*/*", UserRequestFilter);
                //var obj = JsonObject.Parse(json);

                var jwt = new JwtSecurityToken(authInfo["id_token"]);
                var p = jwt.Payload;
                tokens.UserId = (string)p["oid"];  //obj.Get("id");
                tokens.UserName = (string) p["upn"]; //obj.Get("login");
                tokens.DisplayName = (string) p["name"]; //obj.Get("name");
                //tokens.Email = (string) p["email"]; // obj.Get("email");
                //tokens.Company = obj.Get("company");
                //tokens.Country = obj.Get("country");

                //if (SaveExtendedUserInfo)
                //{
                //    obj.Each(x => authInfo[x.Key] = x.Value);
                //}

                //string profileUrl;
                //if (obj.TryGetValue("avatar_url", out profileUrl))
                //    tokens.Items[AuthMetadataProvider.ProfileUrlKey] = profileUrl;
            }
            catch (Exception ex)
            {
                Log.Error("Could not retrieve user info", ex);
                //Log.Error("Could not retrieve github user info for '{0}'".Fmt(tokens.DisplayName), ex);
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
