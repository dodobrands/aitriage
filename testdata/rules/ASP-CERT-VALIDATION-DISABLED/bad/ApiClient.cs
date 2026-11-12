using System.Net.Http;

public static class ApiClient
{
    public static HttpClient Create()
    {
        var handler = new HttpClientHandler
        {
            // ruleid: ASP-CERT-VALIDATION-DISABLED
            ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true
        };
        return new HttpClient(handler);
    }
}
