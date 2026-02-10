<?php
// LDAP Injection: should NOT trigger the rule
// 使用 ldap_escape 進行參數化

// 安全：使用 ldap_escape 跳脫使用者輸入
$safeUser = ldap_escape($username, '', LDAP_ESCAPE_FILTER);
$results = ldap_search($conn, "dc=example,dc=com", "(uid=" . $safeUser . ")");

// 安全：使用硬編碼的 filter
$results = ldap_search($conn, "dc=example,dc=com", "(objectClass=user)");

