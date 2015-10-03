namespace ServiceStack.Authentication.Aad.SelfHostTest
{
    public class Services : Service
    {
        public object Any(AzurePortalRequest request)
        {
            return HttpResult.Redirect("https://portal.azure.com");
        }

        public object Any(SecureResourceRequest request)
        {
            var html = @"
<html><body>
<p>
Success!  You are looking at a secure resource.
</p>
<p>
<a href='/auth/logout'>Sign out</a>
</p>
</body></html>
";
            return new HttpResult(html, "text/html");
        }
    }
}