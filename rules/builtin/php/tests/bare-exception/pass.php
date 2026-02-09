<?php
// 良好：捕捉具體的例外類型
try {
    $data = fetchData();
} catch (HttpException $e) {
    error_log('HTTP error: ' . $e->getMessage());
} catch (TimeoutException $e) {
    error_log('Timeout: ' . $e->getMessage());
}

// 良好：捕捉特定的 SPL 例外
try {
    $result = processOrder($order);
} catch (InvalidArgumentException $e) {
    handleValidationError($e);
} catch (RuntimeException $e) {
    handleRuntimeError($e);
}
