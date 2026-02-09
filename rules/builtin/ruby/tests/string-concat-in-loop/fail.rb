# 不良：在迴圈中使用 += 進行字串串接
class CsvBuilder
  def build_csv(rows)
    result = ""
    i = 0
    while i < rows.length
      result += rows[i].join(",")
      result += "\n"
      i += 1
    end
    result
  end
end
