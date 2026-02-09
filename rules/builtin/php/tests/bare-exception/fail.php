<?php
// 不良：捕捉泛型 Exception
try {
    $data = fetchData();
} catch (Exception $e) {
    error_log($e->getMessage());
}

// 不良：捕捉完整命名空間的 Exception
try {
    $result = processOrder($order);
} catch (\Exception $e) {
    handleError($e);
}
