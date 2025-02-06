package com.springboot.helper;

import com.springboot.order.entity.Order;

public class StampCalculator {
    public static int calculateStampCount(int nowCount, int earned) {
        return nowCount + earned;
    }

    public static int calculateEarnedStampCount(Order order) {
        return order.getOrderCoffees().stream()
                .map(orderCoffee -> orderCoffee.getQuantity())
                .mapToInt(quantity -> quantity)
                .sum();
    }
}
