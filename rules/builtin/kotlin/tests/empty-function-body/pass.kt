class EventHandler {
    // 好：函式有實作邏輯
    fun onStart() {
        initialize()
    }

    fun onClick() {
        handleClick()
    }

    fun onResume() {
        // 故意為空：此事件不需要處理
        return
    }
}
