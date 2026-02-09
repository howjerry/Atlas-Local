<?php
// 安全：使用 htmlspecialchars 跳脫輸出
echo htmlspecialchars($userInput, ENT_QUOTES, 'UTF-8');

// 安全：輸出純字串常數
echo "Welcome to our site!";

// 安全：使用 htmlentities 跳脫
echo htmlentities($data, ENT_QUOTES, 'UTF-8');

// 安全：輸出整數
echo 42;
