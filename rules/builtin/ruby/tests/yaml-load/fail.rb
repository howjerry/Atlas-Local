# 不安全：使用 YAML.load 反序列化不受信任的資料
require "yaml"

class ConfigLoader
  def load_config(input)
    YAML.load(input)
  end

  def parse_file(path)
    data = File.read(path)
    YAML.load(data)
  end
end
