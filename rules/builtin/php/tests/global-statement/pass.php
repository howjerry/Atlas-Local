<?php
// 良好：使用參數注入依賴
function getConfig(array $config) {
    return $config['database'];
}

// 良好：使用依賴注入
class RequestProcessor {
    private $db;
    private $logger;

    public function __construct(Database $db, Logger $logger) {
        $this->db = $db;
        $this->logger = $logger;
    }

    public function process() {
        $this->logger->info('Processing request');
        return $this->db->query('SELECT 1');
    }
}
