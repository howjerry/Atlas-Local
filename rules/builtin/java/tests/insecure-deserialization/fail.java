// Insecure Deserialization: SHOULD trigger the rule
// Pattern: readObject() or readUnshared() calls
// NOTE: This is a SAST test fixture intentionally containing vulnerable code patterns

import java.io.*;

public class DeserializationFail {
    public Object deserialize(InputStream input) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(input);
        Object obj = ois.readObject();
        return obj;
    }

    public Object deserializeUnshared(InputStream input) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(input);
        return ois.readUnshared();
    }
}
