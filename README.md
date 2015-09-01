# ServiceStack.Authentication.Aad

[![Build status](https://ci.appveyor.com/api/projects/status/np8eund073tvdrvn?svg=true)](https://ci.appveyor.com/project/jfoshee/servicestack-authentication-aad)

Azure Active Directory Authentication plugin for ServiceStack

## Usage

Construct an  `AadAuthProvider` and pass it to your `AuthFeature` plugin 
(along with any other auth providers you may have) inside `AppHost.Configure`.

    public class AppHost : AppSelfHostBase
    {
        public override void Configure(Container container)
        {
            var authProviders = new IAuthProvider[] { new AadAuthProvider(AppSettings) };
            Plugins.Add(new AuthFeature(
                () => new AuthUserSession(), 
                authProviders,
                htmlRedirect: "/auth/aad"));
        }
    }

You must provide the `ClientId` and `ClientSecret`.
They can be provided to the constructor, by setting the properties,
or in the web.config appSettings under the following keys: 
`oauth.aad.ClientId` and `oauth.aad.ClientSecret`.

For example:

	<configuration>
		<appSettings>
			<add key="oauth.aad.ClientId" value="00000000-0000-0000-0000-000000000000"/>
			<add key="oauth.aad.ClientSecret" value="0000000000000000000000000000000000000000000="/>
		</appSettings>
	</configuration>


You may also provide the `TenantId` of your AAD resource.
The Tenant ID can be found in the oauth2 endpoint as shown:
`https://login.microsoftonline.com/{TenantId}/oauth2/token`
If no Tenant ID is provided the `common` tenant will be used.

The `CallbackUrl` will default
to the /auth/aad path, but it can be configured explicitly. In either
case it must match what has been configured on Azure as a "REPLY URL".

The following properties are not used. If any are configured a warning
will be logged. This can be disabled with `LogConfigurationWarnings`.

- `RedirectUrl`
- `RequestTokenUrl`

**A complete working example can be seen in 
[ServiceStack.Authentication.Aad.SelfHostTest](./ServiceStack.Authentication.Aad.SelfHostTest)**

## Contribution Guidelines

- Security reviews are most welcome.
- Core logic must be unit tested.
- Unit tests should be written using 3 paragaphs corresponding to [Arrange, Act and Assert](http://c2.com/cgi/wiki?ArrangeActAssert)
- Build must remain clean (no warnings, tests passing)
- Code Analysis issues should not be introduced


