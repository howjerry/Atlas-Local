// Insecure Deserialization: should NOT trigger the rule
// Uses System.Text.Json and safe Newtonsoft.Json settings

using System.Text.Json;
using Newtonsoft.Json;

public class DeserializationPass
{
    public User SafeDeserialize(string json)
    {
        return System.Text.Json.JsonSerializer.Deserialize<User>(json);
    }

    public void SafeJsonSettings()
    {
        var settings = new JsonSerializerSettings();
        settings.TypeNameHandling = TypeNameHandling.None;
    }
}
