using System.IO;
using System.Xml;

public static class XmlImport
{
    // XmlReader.Create prohibits DTDs and has no resolver by default.
    public static XmlReader Open(Stream input) => XmlReader.Create(input);

    public static XmlDocument Load(Stream input)
    {
        var doc = new XmlDocument();
        doc.Load(XmlReader.Create(input, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit }));
        return doc;
    }

    public static XmlTextReader Legacy(Stream input) =>
        new XmlTextReader(input) { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null };
}
