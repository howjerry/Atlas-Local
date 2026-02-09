// XXE 注入: 應該觸發規則
// Pattern: 使用預設的 XML 解析器工廠（未停用外部實體）
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.SAXParserFactory;
import javax.xml.stream.XMLInputFactory;

public class XxeFail {
    // 使用預設 DocumentBuilderFactory（可能允許外部實體）
    public void parseXmlDocument(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.newDocumentBuilder().parse(xml);
    }

    // 使用預設 SAXParserFactory（可能允許外部實體）
    public void parseSaxXml(String xml) throws Exception {
        SAXParserFactory factory = SAXParserFactory.newInstance();
        factory.newSAXParser();
    }

    // 使用預設 XMLInputFactory（可能允許外部實體）
    public void parseStaxXml() throws Exception {
        XMLInputFactory factory = XMLInputFactory.newInstance();
        factory.createXMLStreamReader(System.in);
    }
}
