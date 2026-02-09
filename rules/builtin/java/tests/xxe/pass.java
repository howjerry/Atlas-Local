// XXE 注入: 不應觸發規則
// 使用 JSON 解析或其他不受 XXE 影響的方式

import com.fasterxml.jackson.databind.ObjectMapper;

public class XxePass {
    // 使用 JSON 解析（不受 XXE 影響）
    public Object parseJson(String json) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        return mapper.readValue(json, Object.class);
    }

    // 使用純字串處理（不受 XXE 影響）
    public String extractValue(String data) {
        return data.trim();
    }
}
