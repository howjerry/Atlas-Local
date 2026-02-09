<?php
// 良好：使用命名常數
const MAX_RETRIES = 3;
const UNIT_PRICE = 19;
const LEGAL_AGE = 18;
const DEFAULT_TIMEOUT = 30;

if ($retries > MAX_RETRIES) {
    throw new Exception('Too many retries');
}

$price = $quantity * UNIT_PRICE;

if ($age >= LEGAL_AGE) {
    $allowed = true;
}

$timeout = $base + DEFAULT_TIMEOUT;
