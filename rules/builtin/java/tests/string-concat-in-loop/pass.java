import java.util.List;

public class Pass {
    public String joinItems(List<String> items) {
        StringBuilder sb = new StringBuilder();
        for (String s : items) {
            sb.append(s);
        }
        return sb.toString();
    }

    public String buildReport(String[] lines) {
        StringBuilder output = new StringBuilder();
        for (int i = 0; i < lines.length; i++) {
            output.append(lines[i]).append("\n");
        }
        return output.toString();
    }

    public String joinWithDelimiter(List<String> items) {
        return String.join(", ", items);
    }
}
