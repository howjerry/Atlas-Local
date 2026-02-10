import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.async

// Coroutine Unsafe Context: SHOULD trigger the rule
// Pattern: 使用 GlobalScope 啟動 coroutine 導致非結構化併發

var sharedCounter = 0

fun unsafeCoroutine() {
    // 不安全：GlobalScope.launch 無結構化併發
    GlobalScope.launch() {
        sharedCounter++
    }

    // 不安全：GlobalScope.async 無結構化併發
    GlobalScope.async() {
        sharedCounter * 2
    }
}

