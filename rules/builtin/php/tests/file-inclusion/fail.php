<?php
// 不安全：使用變數作為 include 路徑
$page = $_GET['page'];
include $page;

// 不安全：使用字串插值組合 require 路徑
require "modules/$module.php";

// 不安全：使用變數作為 include_once 路徑
include_once $controllerPath;

// 不安全：使用字串串接組合 require_once 路徑
require_once $baseDir . '/config.php';
