using Funq;
using ServiceStack.Auth;
using ServiceStack.Logging;

namespace ServiceStack.Authentication.Aad.SelfHostTest
{
    public class AppHost : AppSelfHostBase
    {
        public AppHost()
            : base("SelfHostTest", typeof(Services).Assembly)
        {
            Logging.LogManager.LogFactory = new ConsoleLogFactory();
        }

        public override void Configure(Container container)
        {
            var authProviders = new IAuthProvider[] { new AadAuthProvider(AppSettings) };
            Plugins.Add(new AuthFeature(
                () => new AuthUserSession(), 
                authProviders,
                htmlRedirect: "/auth/aad"));
        }
    }
}