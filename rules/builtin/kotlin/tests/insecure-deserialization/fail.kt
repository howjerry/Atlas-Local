import java.io.ObjectInputStream
import java.io.FileInputStream

fun deserializeObject(filename: String): Any {
    // 不安全：從不受信任的來源反序列化物件
    val fis = FileInputStream(filename)
    val ois = ObjectInputStream(fis)
    val obj = ois.readObject()
    ois.close()
    return obj
}
