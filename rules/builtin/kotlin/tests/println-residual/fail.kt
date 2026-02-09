fun processData(data: List<String>) {
    // 不好：println 除錯殘留
    println("Processing data...")
    for (item in data) {
        println(item)
    }
    print("Done")
}
