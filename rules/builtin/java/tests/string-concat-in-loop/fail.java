import java.util.List;

public class Fail {
    public String joinItems(List<String> items) {
        String result = "";
        for (String s : items) {
            result += s;
        }
        return result;
    }

    public String buildReport(String[] lines) {
        String output = "";
        for (int i = 0; i < lines.length; i++) {
            output += lines[i] + "\n";
        }
        return output;
    }

    public String readAll(java.util.Iterator<String> iter) {
        String data = "";
        while (iter.hasNext()) {
            data += iter.next();
        }
        return data;
    }
}
