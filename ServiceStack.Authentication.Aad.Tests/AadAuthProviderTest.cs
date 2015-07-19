using System.Collections.Generic;
using FluentAssertions;
using NUnit.Framework;
using ServiceStack.Auth;
using ServiceStack.Configuration;

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

        // TODO: More meaningful unit tests...
    }
}
