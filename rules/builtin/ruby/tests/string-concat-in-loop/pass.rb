# 良好：使用 << 或 Array#join 取代迴圈中的字串串接
class CsvBuilder
  def build_csv(rows)
    parts = []
    rows.each do |row|
      parts << row.join(",")
    end
    parts.join("\n")
  end

  def build_csv_alt(rows)
    rows.map { |row| row.join(",") }.join("\n")
  end
end
