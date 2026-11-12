using System.IO;
using System.Xml;

public static class LegacyFeed
{
    public static XmlTextReader Open(Stream input)
    {
        // ruleid: ASP-XXE
        var reader = new XmlTextReader(input);
        return reader;
    }
}
