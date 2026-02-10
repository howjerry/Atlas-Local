# XXE: should NOT trigger the rule
# 使用安全的 XML 解析設定

require 'nokogiri'

# 安全：使用預設選項（不啟用外部實體）
doc = Nokogiri::XML(xml_input)

# 安全：明確使用安全選項
doc = Nokogiri::XML.parse(xml_input)

