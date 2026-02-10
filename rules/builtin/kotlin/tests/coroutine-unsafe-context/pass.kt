import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

// Coroutine Unsafe Context: should NOT trigger the rule
// 使用結構化併發和同步機制

val mutex = Mutex()
var safeCounter = 0

suspend fun safeCoroutine() {
    // 安全：使用 coroutineScope 結構化併發
    coroutineScope {
        launch {
            mutex.withLock {
                safeCounter++
            }
        }
    }
}

