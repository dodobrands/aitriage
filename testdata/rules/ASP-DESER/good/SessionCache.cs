using System.Text.Json;
using System.Web.Script.Serialization;

// Migrated away from BinaryFormatter and TypeNameHandling.All in 2023.
public class SessionCache
{
    public Message Load(string body) => JsonSerializer.Deserialize<Message>(body);

    public Message Legacy(string body) => new JavaScriptSerializer().Deserialize<Message>(body);
}
