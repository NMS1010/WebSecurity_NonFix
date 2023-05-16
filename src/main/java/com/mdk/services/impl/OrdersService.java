package com.mdk.services.impl;

import com.mdk.dao.IOrdersDAO;
import com.mdk.dao.impl.OrdersDAO;
import com.mdk.models.OrderDetails;
import com.mdk.models.Orders;
import com.mdk.paging.Pageble;
import com.mdk.services.*;

import java.util.List;

public class OrdersService implements IOrdersService {
    IOrdersDAO ordersDAO = new OrdersDAO();
    @Override
    public List<Orders> findAll(String status) {
        return ordersDAO.findAll(status);
    }
    @Override
    public Orders findOneById(int id) {
        return ordersDAO.findOneById(id);
    }

    @Override
    public Orders findById(int id) {
        return ordersDAO.findById(id);
    }

    @Override
    public void updateStatus(String status, int id) {
        ordersDAO.updateStatus(status, id);
    }

    @Override
    public int count(String status, int storeId, String start, String end) {
        return ordersDAO.count(status, storeId, start, end);
    }
    @Override
    public List<Orders> findAll(String status, Pageble pageble, int storeId, String start, String end) {
        return ordersDAO.findAll(status, pageble, storeId, start, end);
    }

    @Override
    public int countByStoreId(String status, int storeId, String keyword) {
        return ordersDAO.countByStoreId(status, storeId, keyword);
    }

    @Override
    public List<Orders> findAllByStoreId(String status, int storeId, Pageble pageble , String keyword) {
        return ordersDAO.findAllByStoreId(status, storeId, pageble, keyword);
    }

    @Override
    public List<OrderDetails> findDetailByOrderId(int id) {
        return ordersDAO.findDetailByOrderId(id);
    }
	@Override
	public int currentIndex() {
		return ordersDAO.currentIndex();
	}
	@Override
	public void insert(Orders order) {
		ordersDAO.insert(order);
	}

    @Override
    public List<Orders> ordersNew(int storeId) {
        return ordersDAO.ordersNew(storeId);
    }
	@Override
	public List<Orders> findAllByUser(int userId) {
		return ordersDAO.findAllByUser(userId);
	}

    @Override
    public List<Orders> findAllForReport() {
        return ordersDAO.findAllForReport();
    }

}
