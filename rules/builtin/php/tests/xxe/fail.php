<?php
// XXE: SHOULD trigger the rule
// Pattern: 啟用外部實體載入或使用 LIBXML_NOENT
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

// 不安全：明確啟用外部實體載入
libxml_disable_entity_loader(false);

// 不安全：使用 LIBXML_NOENT 解析外部實體
$xml = simplexml_load_string($xmlData, 'SimpleXMLElement', LIBXML_NOENT);

