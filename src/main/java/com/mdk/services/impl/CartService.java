package com.mdk.services.impl;

import java.util.List;

import com.mdk.dao.ICartDAO;
import com.mdk.dao.impl.CartDAO;
import com.mdk.models.Cart;
import com.mdk.services.ICartService;

public class CartService implements ICartService {

	ICartDAO cartDAO = new CartDAO();
	
	@Override
	public void insert(Cart cart) {
		cartDAO.insert(cart);
	}

	@Override
	public void update(Cart cart) {
		cartDAO.update(cart);
	}

	@Override
	public void delete(int id) {
		cartDAO.delete(id);
	}

	@Override
	public List<Cart> findAll() {
		return cartDAO.findAll();
	}

	@Override
	public Cart findById(int id) {
		return cartDAO.findById(id);
	}

	@Override
	public List<Cart> findByUserId(int userId) {
		return cartDAO.findByUserId(userId);
	}

	@Override
	public Cart findByUserAndStore(int userId, int storeId) {
		return cartDAO.findByUserAndStore(userId, storeId);
	}

}
