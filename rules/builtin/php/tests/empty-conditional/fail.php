<?php
// 不良：空的 if 區塊
if ($condition) {
}

// 不良：空的 else 區塊
if ($status === 'active') {
    processUser($user);
} else {
}

// 不良：另一個空的 if 區塊
if ($data !== null) {
}
