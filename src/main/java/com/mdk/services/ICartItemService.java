package com.mdk.services;

import java.util.List;

import com.mdk.models.CartItem;

public interface ICartItemService {
	void insert(CartItem cartItem);

	void update(CartItem cartItem);

	void delete(int id);

	List<CartItem> findAllByCart(int cartId);

	CartItem findOneById(int id);

	CartItem findByCartAndProduct(int cartId, int productId);
}
