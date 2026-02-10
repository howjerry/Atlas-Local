# XML Bomb: should NOT trigger the rule
# 使用 defusedxml 安全的 XML 解析器

import defusedxml.ElementTree as ET
from defusedxml.minidom import parse, parseString

def safe_parse_file(filepath):
    # 安全：使用 defusedxml
    tree = ET.parse(filepath)
    return tree.getroot()

def safe_fromstring(xml_data):
    # 安全：使用 defusedxml fromstring
    root = ET.fromstring(xml_data)
    return root

def safe_minidom(xml_data):
    # 安全：使用 defusedxml minidom
    doc = parseString(xml_data)
    return doc

