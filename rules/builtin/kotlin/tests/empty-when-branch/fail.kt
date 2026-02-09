fun handleStatus(status: Int) {
    when (status) {
        200 -> {
            processSuccess()
        }
        404 -> {
            // 不好：空的 when 分支
        }
        500 -> {
        }
        else -> handleOther()
    }
}
