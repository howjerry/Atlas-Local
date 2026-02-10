# XXE: SHOULD trigger the rule
# Pattern: Nokogiri XML 解析啟用 NOENT
# NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

require 'nokogiri'

# 不安全：使用 NOENT 選項解析 XML
doc = Nokogiri::XML.parse(xml_input, nil, nil, NOENT)

# 不安全：使用完整路徑的 NOENT
doc = Nokogiri::XML.parse(user_xml, nil, nil, Nokogiri::XML::ParseOptions::NOENT)

