import javax.xml.parsers.DocumentBuilderFactory

// XXE: SHOULD trigger the rule
// Pattern: XML parser factory 未停用外部實體

fun parseXml(xmlString: String) {
    // 不安全：使用預設設定建立 DocumentBuilderFactory
    val factory = DocumentBuilderFactory.newInstance()
    val builder = factory.newDocumentBuilder()
}

