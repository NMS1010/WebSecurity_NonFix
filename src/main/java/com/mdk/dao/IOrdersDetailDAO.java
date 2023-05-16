package com.mdk.dao;

import com.mdk.models.OrdersDetail;

public interface IOrdersDetailDAO {
    OrdersDetail findOrderDetailById(int id);
}
