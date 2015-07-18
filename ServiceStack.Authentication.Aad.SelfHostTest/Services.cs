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
            return "Success!";
        }
    }
}