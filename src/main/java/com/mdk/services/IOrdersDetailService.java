package com.mdk.services;

import com.mdk.models.OrdersDetail;

public interface IOrdersDetailService {
    OrdersDetail findOrderDetailById(int id);
}
