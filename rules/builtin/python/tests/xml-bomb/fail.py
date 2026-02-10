# XML Bomb: SHOULD trigger the rule
# Pattern: 使用標準庫的 XML 解析器（容易受到 XML 炸彈攻擊）
# NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import xml.etree.ElementTree as ET
from xml.dom import minidom

def unsafe_parse_file(filepath):
    # 不安全：使用標準 ElementTree parse
    tree = ET.parse(filepath)
    return tree.getroot()

def unsafe_fromstring(xml_data):
    # 不安全：使用 fromstring 解析 XML 字串
    root = ET.fromstring(xml_data)
    return root

def unsafe_minidom(xml_data):
    # 不安全：使用 minidom parseString
    doc = minidom.parseString(xml_data)
    return doc

