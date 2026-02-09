fun processOrder(order: Order) {
    // TODO: 加入訂單驗證邏輯
    order.validate()

    // FIXME: 這裡有競爭條件
    order.process()

    // HACK: 暫時解法，需要重構
    order.save()

    /* XXX: 這個方法太長了 */
}
