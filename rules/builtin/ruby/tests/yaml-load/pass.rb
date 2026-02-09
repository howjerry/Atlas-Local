# 安全：使用 YAML.safe_load 進行安全的反序列化
require "yaml"

class ConfigLoader
  def load_config(input)
    YAML.safe_load(input)
  end

  def parse_with_types(input)
    YAML.safe_load(input, permitted_classes: [Date, Time])
  end
end
