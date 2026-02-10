<?php
// XXE: should NOT trigger the rule
// 使用安全的 XML 解析設定

// 安全：停用外部實體載入
libxml_disable_entity_loader(true);

// 安全：不使用 LIBXML_NOENT
$xml = simplexml_load_string($xmlData);

