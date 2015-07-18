using FluentAssertions;
using NUnit.Framework;
using ServiceStack.Auth;

namespace ServiceStack.Authentication.Aad.Tests
{
    public class AadAuthProviderTest
    {
        [Test]
        public void ShouldBeAuthProvider()
        {
            var subject = new AadAuthProvider();
            subject.Should().BeAssignableTo<AuthProvider>();
        }
    }
}
