<?php
// 不安全：直接 echo 變數（可能含有惡意腳本）
echo $userInput;

// 不安全：echo 字串插值包含變數
echo "Welcome, $username!";

// 不安全：print 變數
print $message;

// 不安全：print 字串插值
print "Result: $data";
