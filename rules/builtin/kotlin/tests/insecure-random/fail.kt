import java.util.Random

fun generateToken(): String {
    // 不安全：使用不安全的偽隨機數產生器
    val rng = Random()
    return rng.nextInt().toString()
}
