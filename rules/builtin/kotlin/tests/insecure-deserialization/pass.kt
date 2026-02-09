import kotlinx.serialization.json.Json
import kotlinx.serialization.decodeFromString

@kotlinx.serialization.Serializable
data class User(val name: String, val email: String)

fun deserializeUser(jsonString: String): User {
    // 安全：使用 kotlinx.serialization JSON 反序列化
    return Json.decodeFromString<User>(jsonString)
}
