package com.mdk.services;

import com.mdk.models.OrderDetails;
import com.mdk.models.Orders;
import com.mdk.paging.Pageble;

import java.util.List;

public interface IOrdersService {
	void insert(Orders order);
    List<Orders> findAll(String status);
    Orders findOneById(int id);
    Orders findById(int id);
    void updateStatus(String status, int id);
    int count(String status, int storeId, String start, String end);
    List<Orders> findAll(String status, Pageble pageble, int storeId, String start, String end);
    int countByStoreId(String status, int storeId, String keyword);
    List<Orders> findAllByStoreId(String status, int storeId, Pageble pageble, String keyword);
    List<OrderDetails> findDetailByOrderId(int id);
    List<Orders> ordersNew(int storeId);
    List<Orders> findAllByUser(int userId);
    List<Orders> findAllForReport();
	int currentIndex();

}
