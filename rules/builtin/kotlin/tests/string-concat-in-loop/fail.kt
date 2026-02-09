fun buildReport(items: List<String>): String {
    var result = ""
    // 不好：在迴圈中使用字串串接
    for (item in items) {
        result += item
    }

    var csv = ""
    var i = 0
    while (i < items.size) {
        csv += items[i]
        i++
    }

    return result
}
