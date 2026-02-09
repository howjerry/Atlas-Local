fun processOrder(order: Order) {
    // 驗證訂單資料
    order.validate()

    // 處理訂單邏輯
    order.process()

    // 儲存訂單至資料庫
    order.save()

    /* 此方法已完成所有必要的訂單處理步驟 */
}
