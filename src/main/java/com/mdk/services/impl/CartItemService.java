package com.mdk.services.impl;

import java.util.List;

import com.mdk.dao.ICartItemDAO;
import com.mdk.dao.impl.CartItemDAO;
import com.mdk.models.CartItem;
import com.mdk.services.ICartItemService;

public class CartItemService implements ICartItemService {

	ICartItemDAO cartItemDAO = new CartItemDAO();
	
	@Override
	public void insert(CartItem cartItem) {
		cartItemDAO.insert(cartItem);
	}

	@Override
	public void update(CartItem cartItem) {
		cartItemDAO.update(cartItem);
	}

	@Override
	public void delete(int id) {
		cartItemDAO.delete(id);
	}

	@Override
	public List<CartItem> findAllByCart(int cartId) {
		return cartItemDAO.findAllByCart(cartId);
	}

	@Override
	public CartItem findOneById(int id) {
		return cartItemDAO.findOneById(id);
	}

	@Override
	public CartItem findByCartAndProduct(int cartId, int productId) {
		return cartItemDAO.findByCartAndProduct(cartId, productId);
	}

}
