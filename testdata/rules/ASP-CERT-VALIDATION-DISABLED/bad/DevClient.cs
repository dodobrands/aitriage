using System.Net.Http;

public static class DevClient
{
    public static HttpClient Create()
    {
        var handler = new HttpClientHandler();
        // ruleid: ASP-CERT-VALIDATION-DISABLED
        handler.ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        return new HttpClient(handler);
    }
}
