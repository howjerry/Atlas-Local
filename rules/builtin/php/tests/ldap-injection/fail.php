<?php
// LDAP Injection: SHOULD trigger the rule
// Pattern: LDAP 搜尋使用字串串接組合 filter
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

// 不安全：使用字串內插組合 LDAP filter
$username = $_GET['username'];
$results = ldap_search($conn, "dc=example,dc=com", "(uid=$username)");

// 不安全：使用字串串接組合 filter
$filter = "(cn=" . $_POST['name'] . ")";
$results = ldap_list($conn, "dc=example,dc=com", $filter);

