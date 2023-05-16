package com.mdk.services.impl;

import com.mdk.dao.IOrdersDetailDAO;
import com.mdk.dao.impl.OrdersDetailDAO;
import com.mdk.models.OrdersDetail;
import com.mdk.services.IOrdersDetailService;

public class OrdersDetailService implements IOrdersDetailService {
    IOrdersDetailDAO iOrdersDetailDAO = new OrdersDetailDAO();
    @Override
    public OrdersDetail findOrderDetailById(int id) {
        return iOrdersDetailDAO.findOrderDetailById(id);
    }
}
