<?php
// 不良：冗餘的布林回傳
function isAdult($age) {
    if ($age >= 18) {
        return true;
    } else {
        return false;
    }
}

// 不良：另一個冗餘布林回傳
function isValid($data) {
    if (!empty($data)) {
        return true;
    } else {
        return false;
    }
}
