package com.mdk.services;

import java.util.List;

import com.mdk.models.Cart;

public interface ICartService {
	void insert(Cart cart);

	void update(Cart cart);

	void delete(int id);

	List<Cart> findAll();

	Cart findById(int id);

	Cart findByUserAndStore(int userId, int storeId);

	List<Cart> findByUserId(int userId);
}
