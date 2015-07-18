using Funq;
using ServiceStack.Auth;

namespace ServiceStack.Authentication.Aad.SelfHostTest
{
    public class AppHost : AppSelfHostBase
    {
        public AppHost()
            : base("SelfHostTest", typeof(Services).Assembly)
        {
        }

        public override void Configure(Container container)
        {
            var authProviders = new IAuthProvider[] { new AadAuthProvider() };
            Plugins.Add(new AuthFeature(() => new AuthUserSession(), authProviders));
        }
    }
}