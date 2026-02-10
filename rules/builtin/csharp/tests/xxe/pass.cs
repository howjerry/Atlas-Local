// XXE: should NOT trigger the rule
// 使用安全的 XML 解析設定

using System.Xml;

public class SafeXml
{
    public XmlReader SafeReaderSettings()
    {
        // 安全：禁止 DTD 處理並設定 XmlResolver 為 null
        var settings = new XmlReaderSettings
        {
            DtdProcessing = DtdProcessing.Prohibit,
            XmlResolver = null
        };
        return XmlReader.Create("data.xml", settings);
    }
}

