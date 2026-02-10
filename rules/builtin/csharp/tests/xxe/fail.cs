// XXE: SHOULD trigger the rule
// Pattern: XML 解析器啟用 DTD 處理或設定不安全的 XmlResolver
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

using System.Xml;

public class UnsafeXml
{
    public void UnsafeDtdProcessing()
    {
        var settings = new XmlReaderSettings();
        // 不安全：啟用 DTD 處理
        settings.DtdProcessing = DtdProcessing.Parse;
    }

    public void UnsafeXmlResolver()
    {
        var doc = new XmlDocument();
        // 不安全：設定 XmlUrlResolver
        doc.XmlResolver = new XmlUrlResolver();
    }

    public void UnsafeProhibitDtd()
    {
        var reader = new XmlTextReader("data.xml");
        // 不安全：禁用 DTD 限制
        reader.ProhibitDtd = false;
    }
}

