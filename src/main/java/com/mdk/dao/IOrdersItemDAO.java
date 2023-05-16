package com.mdk.dao;

import java.util.List;

import com.mdk.models.OrdersItem;

public interface IOrdersItemDAO {
	void insert(OrdersItem orderItem);
	List<OrdersItem> findByOrdersId(int ordersId);
}
