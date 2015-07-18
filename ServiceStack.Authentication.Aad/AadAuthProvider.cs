using ServiceStack.Auth;
using System;

namespace ServiceStack.Authentication.Aad
{
    public class AadAuthProvider : AuthProvider
    {
        public override bool IsAuthorized(IAuthSession session, IAuthTokens tokens, Authenticate request = null)
        {
            throw new NotImplementedException();
        }

        public override object Authenticate(IServiceBase authService, IAuthSession session, Authenticate request)
        {
            throw new NotImplementedException();
        }
    }
}
