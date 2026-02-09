fun handleStatus(status: Int) {
    when (status) {
        200 -> {
            processSuccess()
        }
        404 -> {
            logNotFound()
        }
        500 -> {
            handleServerError()
        }
        else -> handleOther()
    }
}
