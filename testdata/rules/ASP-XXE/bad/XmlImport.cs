using System.IO;
using System.Xml;

public static class XmlImport
{
    public static XmlReader Open(Stream input)
    {
        var settings = new XmlReaderSettings
        {
            // ruleid: ASP-XXE
            DtdProcessing = DtdProcessing.Parse,
            XmlResolver = new XmlUrlResolver()
        };
        return XmlReader.Create(input, settings);
    }
}
