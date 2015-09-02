# <img src="Icon.jpeg" width="51" height="40" >  ServiceStack.Authentication.Aad

[![Build status](https://ci.appveyor.com/api/projects/status/np8eund073tvdrvn?svg=true)](https://ci.appveyor.com/project/jfoshee/servicestack-authentication-aad)
[![NuGet package](https://img.shields.io/nuget/v/ServiceStack.Authentication.Aad.svg)](https://www.nuget.org/packages/ServiceStack.Authentication.Aad)

Azure Active Directory Authentication plugin for ServiceStack

The AadAuthProvider is a great way to add Microsoft organizational authentication 
to some or all of your ServiceStack web site or services.
Azure Active Directory (AAD or formerly WAAD) enables login to custom apps 
when organizations are using Office 365 or a custom AAD resource.

## Azure Configuration

<img src="./documentation/Office 365 Admin Center.PNG" align=right width="110" height="428" >

### Office 365

If you want to enable authentication for an Office365 domain, navigate to your [Office 365 Admin Center](https://portal.office.com/admin/default.aspx). 
At the bottom left, under "ADMIN" click "Azure AD". That should take you to something like: `https://manage.windowsazure.com/{my organization}.com`
Visiting the AAD administration for Office365 the first time may take a moment to setup.

### Add App to AAD

Navigate to your Azure Active Directory and select the Applications tab.

<img src="./documentation/AAD Applications.PNG" width="360" height="228" >

At the bottom click "ADD" then select "Add an application my organization is developing".

Give the application a readable name, select Web application and click the next arrow.

<img src="./documentation/1 Tell us about your app.PNG" width="314" height="225" >
<img src="./documentation/2 Add app urls.PNG" width="314" height="225" >

#### Tenant ID

Click "VIEW ENDPOINTS" at the bottom of your app's quick-start page. 

<img src="./documentation/App endpoints.PNG" width="246" height="307" >

The AadAuthProvider will be using the two OAuth2 endpoints at the bottom.
The AadAuthProvider assumes they have the following format:  
`https://login.microsoftonline.com/00000000-1111-2222-3333-444444444444/oauth2/token`  
`https://login.microsoftonline.com/00000000-1111-2222-3333-444444444444/oauth2/authorize`

Your Tenant ID is the UID in the middle of the URL: `https://login.microsoftonline.com/{TenantID}/oauth2/token` 
You should retain it for later.

##### Endpoints

(_If_ the endpoints do not match the above patterns you can configure them manually 
using the appSettings keys `oauth.aad.AccessTokenUrl` and `oauth.aad.AuthorizeUrl` respectively.)

#### Client ID

Select the CONFIGURE tab and scroll down to find your Client ID. Retain the Client ID for configuration.

<img src="./documentation/3 Configure Client ID.PNG" width="480" height="347" >

#### Client Secret

Under "keys" drop-down the "Select duration" box to pick a 1 or 2 year key lifetime.

<img src="./documentation/4 Select key duration.PNG" width="348" height="92" >

Under "single sign-on" you must supply a "REPLY URL" for each unique URL that will act as an OAuth2 callback. 
The ServiceStack convention is base URL + `/auth/aad`.
So for testing you should add: `http://localhost:1234/auth/aad` (using an obscure port number)
And for your live site you should add: `http://example.com/auth/aad` (using https if applicable)
You can remove the default reply URL if it will not be used as an OAuth2 callback.

<img src="./documentation/5 Save Configuration with client key.PNG" width="452" height="338" >

Finally, click SAVE at the bottom of the CONFIGURE page. After a few seconds the changes should be saved and the new key will be displayed.
Copy and retain the key as the Client Secret (aka Consumer Secret).

### Back on Office 365

Clearly you can also provide an icon for your app.  When your users browse to https://portal.office.com/myapps they will see your custom app 
along with the other Office apps. When they click on your app they will be sent to the configured "SIGN-ON URL".

<img src="./documentation/My Office Apps.PNG" width="452" height="338" >


## `AadAuthProvider` Usage

Construct an  **`AadAuthProvider`** and pass it to your `AuthFeature` plugin 
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
			<!-- Optional: -->
			<add key="oauth.aad.TenantId" value="00000000-0000-0000-0000-000000000000"/>
		    <add key="oauth.aad.DomainHint" value="example.onmicrosoft.com"/>
		</appSettings>
	</configuration>

#### Optional Configuration

You _should_ also provide the `TenantId` of your AAD resource, though it is not required.
The Tenant ID can be found in the oauth2 endpoint as shown:
`https://login.microsoftonline.com/{TenantId}/oauth2/token`
If a Tenant ID is provided and the user logs into a different tenant, the authentication will fail.
If no Tenant ID is provided the `common` tenant will be used. 
(In practice Microsoft may permit the user to log into a different tenant
than the one associated with the given Tenant ID and Client ID.
So the way we prevent logging in via the wrong domain is by checking authenticated user's Tenant ID.)

You may configure a `DomainHint`. This will be passed to Microsoft when initiating
the OAuth2 login. In theory users with multiple logins will have help picking the right one.
In practice Microsoft does not always respect this value. It does not provide any security.

You may configure a `ResourceId` for the AAD resource for which the access token is being requested.
This defaults to the directory resource so we can get the user's info. 
Changing the ResourceId may have other implications, so contact us if this is a feature you need.

The `CallbackUrl` will default
to the `.../auth/aad` path, but it can be configured explicitly. In either
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


