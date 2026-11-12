using System.Net.Http;
using System.Net.Security;

public static class ApiClient
{
    public static HttpClient Create()
    {
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => errors == SslPolicyErrors.None
        };
        return new HttpClient(handler);
    }
}
