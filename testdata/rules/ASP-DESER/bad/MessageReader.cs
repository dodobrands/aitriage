using Newtonsoft.Json;

public static class MessageReader
{
    public static object Read(string json)
    {
        var settings = new JsonSerializerSettings
        {
            // ruleid: ASP-DESER
            TypeNameHandling = TypeNameHandling.Auto
        };
        return JsonConvert.DeserializeObject(json, settings);
    }
}
