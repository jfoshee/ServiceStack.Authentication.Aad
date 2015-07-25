using FluentAssertions;
using Moq;
using NUnit.Framework;
using ServiceStack.Auth;
using ServiceStack.Configuration;
using ServiceStack.Testing;
using ServiceStack.Web;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;

namespace ServiceStack.Authentication.Aad.Tests
{
    public class AadAuthProviderTest
    {
        public AadAuthProvider Subject { get; set; }

        [SetUp]
        public void Setup()
        {
            Subject = new AadAuthProvider();    
        }

        [Test]
        public void ShouldBeAuthProvider()
        {
            Subject.Should().BeAssignableTo<AuthProvider>();
            Subject.Provider.Should().Be("aad");
        }

        [Test]
        public void ShouldInitializeSettings()
        {
            var settings = new Dictionary<string, string>
            {
                { "oauth.aad.TenantId", "tenant789" },
                { "oauth.aad.ClientId", "client1234" },
                { "oauth.aad.ClientSecret", "secret456" },
            };
            var appSettings = new DictionarySettings(settings);

            Subject = new AadAuthProvider(appSettings);

            Subject.TenantId.Should().Be("tenant789");
            Subject.ClientId.Should().Be("client1234");
            Subject.ClientSecret.Should().Be("secret456");
            Subject.ConsumerKey.Should().Be(Subject.ClientId);
            Subject.ConsumerSecret.Should().Be(Subject.ClientSecret);
            Subject.AuthorizeUrl.Should().Be("https://login.microsoftonline.com/tenant789/oauth2/authorize");
            Subject.AccessTokenUrl.Should().Be("https://login.microsoftonline.com/tenant789/oauth2/token");
        }

        [Test]
        public void ShouldUseGivenUrls()
        {
            var settings = new Dictionary<string, string>
            {
                { "oauth.aad.AuthorizeUrl", "https://authorize.example" },
                { "oauth.aad.AccessTokenUrl", "https://token.example" },
            };
            var appSettings = new DictionarySettings(settings);

            Subject = new AadAuthProvider(appSettings);

            Subject.AuthorizeUrl.Should().Be("https://authorize.example");
            Subject.AccessTokenUrl.Should().Be("https://token.example");
        }

        [Test]
        public void ShouldUseCommonEndpointWhenTenantIdMissing()
        {
            Subject.AuthorizeUrl.Should().Be("https://login.microsoftonline.com/common/oauth2/authorize");
            Subject.AccessTokenUrl.Should().Be("https://login.microsoftonline.com/common/oauth2/token");
        }

        [Test]
        public void ShouldUpdateEndpointsWhenTenantIdChanged()
        {
            Subject.TenantId = "tid123";
            Subject.AuthorizeUrl.Should().Be("https://login.microsoftonline.com/tid123/oauth2/authorize");
            Subject.AccessTokenUrl.Should().Be("https://login.microsoftonline.com/tid123/oauth2/token");
            Subject.TenantId = String.Empty;
            ShouldUseCommonEndpointWhenTenantIdMissing();
            Subject.TenantId = null;
            ShouldUseCommonEndpointWhenTenantIdMissing();
        }

        // Tests based on examples at https://msdn.microsoft.com/en-us/library/azure/dn645542.aspx

        [Test]
        public void ShouldRequestCode()
        {
            using (TestAppHost())
            {
                Subject.ClientId = "2d4d11a2-f814-46a7-890a-274a72a7309e";
                Subject.CallbackUrl = "http://localhost/myapp/";
                // TODO: It is confusing that there is a CallbackUrl and a RedirectUrl
                var mockAuthService = MockAuthService();

                var response = Subject.Authenticate(mockAuthService.Object, new AuthUserSession(), new Authenticate());

                var result = (IHttpResult) response;
                result.Headers["Location"].Should().StartWith(
                    "https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=2d4d11a2-f814-46a7-890a-274a72a7309e&redirect_uri=http%3a%2f%2flocalhost%2fmyapp%2f");
            }
        }

        [Test]
        public void ShouldRequestToken()
        {
            // When an application sends a GET request for an authorization code, Azure AD sends a response to the
            // value of the redirect_uri parameter in the request. The response includes the following parameters:
            //      [admin_consent], code, session_state, state
            using (TestAppHost())
            {
                Subject.ClientId = "2d4d11a2-f814-46a7-890a-274a72a7309e";
                // TODO: Subject.TenantId
                Subject.CallbackUrl = "http://localhost/myapp/";
                var request = new MockHttpRequest("myapp", "GET", "text", "/myapp", new NameValueCollection {
                    {"code", "AwABAAAAvPM1KaPlrEqdFSBzjqfTGBCmLdgfSTLEMPGYuNHSUYBrqqf_ZT_p5uEAEJJ_nZ3UmphWygRNy2C3jJ239gV_DBnZ2syeg95Ki-374WHUP-i3yIhv5i-7KU2CEoPXwURQp6IVYMw-DjAOzn7C3JCu5wpngXmbZKtJdWmiBzHpcO2aICJPu1KvJrDLDP20chJBXzVYJtkfjviLNNW7l7Y3ydcHDsBRKZc3GuMQanmcghXPyoDg41g8XbwPudVh7uCmUponBQpIhbuffFP_tbV8SNzsPoFz9CLpBCZagJVXeqWoYMPe2dSsPiLO9Alf_YIe5zpi-zY4C3aLw5g9at35eZTfNd0gBRpR5ojkMIcZZ6IgAA"},
                    {"session_state", "7B29111D-C220-4263-99AB-6F6E135D75EF"},
                    {"state", "D79E5777-702E-4260-9A62-37F75FF22CCE" }
                }, Stream.Null, null);
                var mockAuthService = MockAuthService(request);
                using (new HttpResultsFilter
                {
                    StringResultFn = (tokenRequest) =>
                    {
                        // To redeem an authorization code and get an access token,
                        // send an HTTP POST request to a common or tenant-specific Azure AD Authorization endpoint.
                        tokenRequest.RequestUri.ToString().Should().Be(
                            "https://login.microsoftonline.com/common/oauth2/token");
                        tokenRequest.Method.Should().Be("POST");
                        tokenRequest.ContentType.Should().Be("application/x-www-form-urlencoded");
                        // TODO: Test form data. Seems impossible: http://stackoverflow.com/questions/31630526/can-i-test-form-data-using-httpresultsfilter-callback
                        //formData["client_id"].Should().Be(Subject.ClientId);
                        //formData["redirect_uri"]
                        return 
                        @"{
                          ""access_token"": ""eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik5HVEZ2ZEstZnl0aEV1THdqcHdBSk9NOW4tQSJ9.eyJhdWQiOiJodHRwczovL3NlcnZpY2UuY29udG9zby5jb20vIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvN2ZlODE0NDctZGE1Ny00Mzg1LWJlY2ItNmRlNTdmMjE0NzdlLyIsImlhdCI6MTM4ODQ0MDg2MywibmJmIjoxMzg4NDQwODYzLCJleHAiOjEzODg0NDQ3NjMsInZlciI6IjEuMCIsInRpZCI6IjdmZTgxNDQ3LWRhNTctNDM4NS1iZWNiLTZkZTU3ZjIxNDc3ZSIsIm9pZCI6IjY4Mzg5YWUyLTYyZmEtNGIxOC05MWZlLTUzZGQxMDlkNzRmNSIsInVwbiI6ImZyYW5rbUBjb250b3NvLmNvbSIsInVuaXF1ZV9uYW1lIjoiZnJhbmttQGNvbnRvc28uY29tIiwic3ViIjoiZGVOcUlqOUlPRTlQV0pXYkhzZnRYdDJFYWJQVmwwQ2o4UUFtZWZSTFY5OCIsImZhbWlseV9uYW1lIjoiTWlsbGVyIiwiZ2l2ZW5fbmFtZSI6IkZyYW5rIiwiYXBwaWQiOiIyZDRkMTFhMi1mODE0LTQ2YTctODkwYS0yNzRhNzJhNzMwOWUiLCJhcHBpZGFjciI6IjAiLCJzY3AiOiJ1c2VyX2ltcGVyc29uYXRpb24iLCJhY3IiOiIxIn0.JZw8jC0gptZxVC-7l5sFkdnJgP3_tRjeQEPgUn28XctVe3QqmheLZw7QVZDPCyGycDWBaqy7FLpSekET_BftDkewRhyHk9FW_KeEz0ch2c3i08NGNDbr6XYGVayNuSesYk5Aw_p3ICRlUV1bqEwk-Jkzs9EEkQg4hbefqJS6yS1HoV_2EsEhpd_wCQpxK89WPs3hLYZETRJtG5kvCCEOvSHXmDE6eTHGTnEgsIk--UlPe275Dvou4gEAwLofhLDQbMSjnlV5VLsjimNBVcSRFShoxmQwBJR_b2011Y5IuD6St5zPnzruBbZYkGNurQK63TJPWmRd3mbJsGM0mf3CUQ"",
                          ""token_type"": ""Bearer"",
                          ""expires_in"": ""3600"",
                          ""expires_on"": ""1388444763"",
                          ""resource"": ""https://service.contoso.com/"",
                          ""refresh_token"": ""AwABAAAAvPM1KaPlrEqdFSBzjqfTGAMxZGUTdM0t4B4rTfgV29ghDOHRc2B-C_hHeJaJICqjZ3mY2b_YNqmf9SoAylD1PycGCB90xzZeEDg6oBzOIPfYsbDWNf621pKo2Q3GGTHYlmNfwoc-OlrxK69hkha2CF12azM_NYhgO668yfcUl4VBbiSHZyd1NVZG5QTIOcbObu3qnLutbpadZGAxqjIbMkQ2bQS09fTrjMBtDE3D6kSMIodpCecoANon9b0LATkpitimVCrl-NyfN3oyG4ZCWu18M9-vEou4Sq-1oMDzExgAf61noxzkNiaTecM-Ve5cq6wHqYQjfV9DOz4lbceuYCAA"",
                          ""scope"": ""user_impersonation"",
                          ""id_token"": ""eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiIyZDRkMTFhMi1mODE0LTQ2YTctODkwYS0yNzRhNzJhNzMwOWUiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC83ZmU4MTQ0Ny1kYTU3LTQzODUtYmVjYi02ZGU1N2YyMTQ3N2UvIiwiaWF0IjoxMzg4NDQwODYzLCJuYmYiOjEzODg0NDA4NjMsImV4cCI6MTM4ODQ0NDc2MywidmVyIjoiMS4wIiwidGlkIjoiN2ZlODE0NDctZGE1Ny00Mzg1LWJlY2ItNmRlNTdmMjE0NzdlIiwib2lkIjoiNjgzODlhZTItNjJmYS00YjE4LTkxZmUtNTNkZDEwOWQ3NGY1IiwidXBuIjoiZnJhbmttQGNvbnRvc28uY29tIiwidW5pcXVlX25hbWUiOiJmcmFua21AY29udG9zby5jb20iLCJzdWIiOiJKV3ZZZENXUGhobHBTMVpzZjd5WVV4U2hVd3RVbTV5elBtd18talgzZkhZIiwiZmFtaWx5X25hbWUiOiJNaWxsZXIiLCJnaXZlbl9uYW1lIjoiRnJhbmsifQ.""
                        }";
                    }
                })
                {
                    var session = new AuthUserSession();

                    var response = Subject.Authenticate(mockAuthService.Object, session, new Authenticate());

                    session.IsAuthenticated.Should().BeTrue();
                    var tokens = session.GetOAuthTokens("aad");
                    tokens.Provider.Should().Be("aad");
                    tokens.AccessTokenSecret.Should().Be("eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik5HVEZ2ZEstZnl0aEV1THdqcHdBSk9NOW4tQSJ9.eyJhdWQiOiJodHRwczovL3NlcnZpY2UuY29udG9zby5jb20vIiwiaXNzIjoiaHR0cHM6Ly9zdHMud2luZG93cy5uZXQvN2ZlODE0NDctZGE1Ny00Mzg1LWJlY2ItNmRlNTdmMjE0NzdlLyIsImlhdCI6MTM4ODQ0MDg2MywibmJmIjoxMzg4NDQwODYzLCJleHAiOjEzODg0NDQ3NjMsInZlciI6IjEuMCIsInRpZCI6IjdmZTgxNDQ3LWRhNTctNDM4NS1iZWNiLTZkZTU3ZjIxNDc3ZSIsIm9pZCI6IjY4Mzg5YWUyLTYyZmEtNGIxOC05MWZlLTUzZGQxMDlkNzRmNSIsInVwbiI6ImZyYW5rbUBjb250b3NvLmNvbSIsInVuaXF1ZV9uYW1lIjoiZnJhbmttQGNvbnRvc28uY29tIiwic3ViIjoiZGVOcUlqOUlPRTlQV0pXYkhzZnRYdDJFYWJQVmwwQ2o4UUFtZWZSTFY5OCIsImZhbWlseV9uYW1lIjoiTWlsbGVyIiwiZ2l2ZW5fbmFtZSI6IkZyYW5rIiwiYXBwaWQiOiIyZDRkMTFhMi1mODE0LTQ2YTctODkwYS0yNzRhNzJhNzMwOWUiLCJhcHBpZGFjciI6IjAiLCJzY3AiOiJ1c2VyX2ltcGVyc29uYXRpb24iLCJhY3IiOiIxIn0.JZw8jC0gptZxVC-7l5sFkdnJgP3_tRjeQEPgUn28XctVe3QqmheLZw7QVZDPCyGycDWBaqy7FLpSekET_BftDkewRhyHk9FW_KeEz0ch2c3i08NGNDbr6XYGVayNuSesYk5Aw_p3ICRlUV1bqEwk-Jkzs9EEkQg4hbefqJS6yS1HoV_2EsEhpd_wCQpxK89WPs3hLYZETRJtG5kvCCEOvSHXmDE6eTHGTnEgsIk--UlPe275Dvou4gEAwLofhLDQbMSjnlV5VLsjimNBVcSRFShoxmQwBJR_b2011Y5IuD6St5zPnzruBbZYkGNurQK63TJPWmRd3mbJsGM0mf3CUQ");
                    tokens.RefreshTokenExpiry.Should().Be(DateTime.Parse("Mon, 30 Dec 2013 23:06:03 GMT").ToUniversalTime());
                    tokens.RefreshToken.Should().Be("AwABAAAAvPM1KaPlrEqdFSBzjqfTGAMxZGUTdM0t4B4rTfgV29ghDOHRc2B-C_hHeJaJICqjZ3mY2b_YNqmf9SoAylD1PycGCB90xzZeEDg6oBzOIPfYsbDWNf621pKo2Q3GGTHYlmNfwoc-OlrxK69hkha2CF12azM_NYhgO668yfcUl4VBbiSHZyd1NVZG5QTIOcbObu3qnLutbpadZGAxqjIbMkQ2bQS09fTrjMBtDE3D6kSMIodpCecoANon9b0LATkpitimVCrl-NyfN3oyG4ZCWu18M9-vEou4Sq-1oMDzExgAf61noxzkNiaTecM-Ve5cq6wHqYQjfV9DOz4lbceuYCAA");
                    tokens.UserId.Should().Be("68389ae2-62fa-4b18-91fe-53dd109d74f5"); // oid
                    tokens.UserName.Should().Be("frankm@contoso.com");
                    tokens.LastName.Should().Be("Miller");
                    tokens.FirstName.Should().Be("Frank");
                    tokens.DisplayName.Should().Be("Frank Miller");
                    session.UserName.Should().Be(tokens.UserName);
                    session.LastName.Should().Be(tokens.LastName);
                    session.FirstName.Should().Be(tokens.FirstName);
                    session.DisplayName.Should().Be(tokens.DisplayName);
                    var result = (IHttpResult) response;
                    result.Headers["Location"].Should().StartWith(
                        "http://localhost#s=1");
                }
            }
        }

        [Test]
        public void ShouldSetReferrerFromRedirectParam()
        {
            // TODO: Do I really need to create an apphost so that it won't die trying to get the base URL?
            using (TestAppHost())
            {
                var request = new MockHttpRequest("myapp", "GET", "text", "/myapp", new NameValueCollection {
                    {"redirect", "http://localhost/myapp/secure-resource"}
                }, Stream.Null, null);
                var mockAuthService = MockAuthService(request);
                var session = new AuthUserSession();
                
                Subject.Authenticate(mockAuthService.Object, session, new Authenticate());

                session.ReferrerUrl.Should().Be("http://localhost/myapp/secure-resource");
            }
        }

        [Test]
        public void ShouldNotAuthenticateIfTenantIdNotMatched()
        {
            Subject.ClientId = "2d4d11a2-f814-46a7-890a-274a72a7309e";
            Subject.TenantId = "different";
            VerifyNotAuthenticatedByToken();
        }

        [Test]
        public void ShouldNotAuthenticateIfClientIdNotMatched()
        {
            Subject.ClientId = "different";
            VerifyNotAuthenticatedByToken();
        }

        private void VerifyNotAuthenticatedByToken()
        {
            Subject.CallbackUrl = "http://localhost/myapp/";
            using (TestAppHost())
            {
                var request = new MockHttpRequest("myapp", "GET", "text", "/myapp", new NameValueCollection
                {
                    {"code", "code123"},
                    {"state", "D79E5777-702E-4260-9A62-37F75FF22CCE"}
                }, Stream.Null, null);
                var mockAuthService = MockAuthService(request);
                using (new HttpResultsFilter
                {
                    StringResult =
                        @"{
                          ""access_token"": ""token456"",
                          ""id_token"": ""eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiIyZDRkMTFhMi1mODE0LTQ2YTctODkwYS0yNzRhNzJhNzMwOWUiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC83ZmU4MTQ0Ny1kYTU3LTQzODUtYmVjYi02ZGU1N2YyMTQ3N2UvIiwiaWF0IjoxMzg4NDQwODYzLCJuYmYiOjEzODg0NDA4NjMsImV4cCI6MTM4ODQ0NDc2MywidmVyIjoiMS4wIiwidGlkIjoiN2ZlODE0NDctZGE1Ny00Mzg1LWJlY2ItNmRlNTdmMjE0NzdlIiwib2lkIjoiNjgzODlhZTItNjJmYS00YjE4LTkxZmUtNTNkZDEwOWQ3NGY1IiwidXBuIjoiZnJhbmttQGNvbnRvc28uY29tIiwidW5pcXVlX25hbWUiOiJmcmFua21AY29udG9zby5jb20iLCJzdWIiOiJKV3ZZZENXUGhobHBTMVpzZjd5WVV4U2hVd3RVbTV5elBtd18talgzZkhZIiwiZmFtaWx5X25hbWUiOiJNaWxsZXIiLCJnaXZlbl9uYW1lIjoiRnJhbmsifQ.""
                        }"
                })
                {
                    var session = new AuthUserSession();
                    try
                    {
                        Subject.Authenticate(mockAuthService.Object, session, new Authenticate());
                    }
                    catch (UnauthorizedAccessException)
                    {
                    }
                    session.IsAuthenticated.Should().BeFalse();
                }
            }
        }

        private static Mock<IServiceBase> MockAuthService(MockHttpRequest request = null)
        {
            request = request ?? new MockHttpRequest();
            var mockAuthService = new Mock<IServiceBase>();
            mockAuthService.SetupGet(s => s.Request).Returns(request);
            return mockAuthService;
        }

        private IDisposable TestAppHost()
        {
            // TODO: Do I really need to create an apphost so that it won't die trying to get the base URL?
            return new BasicAppHost(typeof(Service).Assembly).Init();
        }

        // TODO: If the state value in the response matches the state value in the request, the application should store the authorization code for use in the access token request.
        // TODO: Use the refresh token to request a new access token
        // TODO: Consumer can provide a different resource id
    }
}
