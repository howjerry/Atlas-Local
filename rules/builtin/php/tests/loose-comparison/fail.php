<?php
// 不良：使用鬆散比較（型別轉換可能導致非預期結果）
if ($value == 0) {
    echo "zero";
}

// 不良："0" == false 結果為 true
if ($input == false) {
    echo "falsy";
}

// 不良：使用 != 鬆散不等比較
if ($status != "active") {
    echo "inactive";
}

// 不良："0e1" == "0e2" 結果為 true（科學記號比較）
if ($hash1 == $hash2) {
    echo "match";
}
