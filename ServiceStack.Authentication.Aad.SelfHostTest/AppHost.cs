using Funq;

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
        }
    }
}