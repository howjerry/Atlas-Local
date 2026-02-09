<?php
// 良好：使用嚴格比較
if ($value === 0) {
    echo "zero";
}

// 良好：使用嚴格不等比較
if ($status !== "active") {
    echo "inactive";
}

// 良好：使用嚴格比較檢查布林值
if ($input === false) {
    echo "falsy";
}

// 良好：使用 hash_equals 比較雜湊
if (hash_equals($hash1, $hash2)) {
    echo "match";
}
