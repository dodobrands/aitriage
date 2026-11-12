using System.IO;
using System.Runtime.Serialization.Formatters.Binary;

public class SessionCache
{
    public object Load(Stream stream)
    {
        // ruleid: ASP-DESER
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(stream);
    }
}
