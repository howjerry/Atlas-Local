import javax.xml.parsers.DocumentBuilderFactory

// XXE: should NOT trigger the rule
// 使用安全設定的 XML 解析

fun parseXmlSafely(xmlString: String) {
    // 安全：使用 Kotlin XML 庫搭配安全設定
    val factory = DocumentBuilderFactory.newInstance().apply {
        setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        setFeature("http://xml.org/sax/features/external-general-entities", false)
    }
    val builder = factory.newDocumentBuilder()
}

