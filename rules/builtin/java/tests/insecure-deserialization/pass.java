// Insecure Deserialization: should NOT trigger the rule
// Uses JSON parsing instead of native Java deserialization

import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.*;

public class DeserializationPass {
    public User deserializeSafe(InputStream input) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(input, User.class);
    }

    public Config parseConfig(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, Config.class);
    }
}
