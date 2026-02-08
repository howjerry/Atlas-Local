// Insecure Deserialization: SHOULD trigger the rule
// Pattern: BinaryFormatter.Deserialize() and TypeNameHandling.All
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using Newtonsoft.Json;

public class DeserializationFail
{
    public object UnsafeDeserialize(Stream stream)
    {
        var formatter = new BinaryFormatter();
        return formatter.Deserialize(stream);
    }

    public void UnsafeJsonSettings()
    {
        var settings = new JsonSerializerSettings();
        settings.TypeNameHandling = TypeNameHandling.All;
    }
}
