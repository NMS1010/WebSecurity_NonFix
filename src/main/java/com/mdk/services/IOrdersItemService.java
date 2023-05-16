package com.mdk.services;

import java.util.List;

import com.mdk.models.OrdersItem;

public interface IOrdersItemService {
	void insert(OrdersItem orderItem);
	List<OrdersItem> findByOrdersId(int ordersId);
}
