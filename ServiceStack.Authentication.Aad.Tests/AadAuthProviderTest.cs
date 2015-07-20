using FluentAssertions;
using Moq;
using NUnit.Framework;
using ServiceStack.Auth;
using ServiceStack.Configuration;
using ServiceStack.Testing;
using ServiceStack.Web;
using System.Collections.Generic;

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
        public void ShouldRequestCode()
        {
            //HostConfig.ResetInstance();
            //HostConfig.Instance.WebHostUrl = "http://localhost";
            // TODO: Do I really need to create an apphost so that it won't die trying to get the base URL?
            using (var appHost = new BasicAppHost(typeof (Service).Assembly).Init())
            {
                Subject.ClientId = "2d4d11a2-f814-46a7-890a-274a72a7309e";
                Subject.ClientSecret = "s34";
                Subject.CallbackUrl = "http://localhost/myapp/";
                // TODO: It is confusing that there is a CallbackUrl and a RedirectUrl
                var mockAuthService = new Mock<IServiceBase>();
                mockAuthService.SetupGet(s => s.Request).Returns(new MockHttpRequest());

                var response = Subject.Authenticate(mockAuthService.Object, new AuthUserSession(), new Authenticate());

                var result = (IHttpResult) response;
                result.Headers["Location"].Should().StartWith(
                    "https://login.microsoftonline.com/common/oauth2/authorize?response_type=code&client_id=2d4d11a2-f814-46a7-890a-274a72a7309e&redirect_uri=http%3a%2f%2flocalhost%2fmyapp%2f");
            }
        }

        // TODO: More meaningful unit tests...
    }
}
