package com.mdk.models;

import java.util.List;

public class Cart extends AbstractModel<Cart> {
	private int userId;
	private int storeId;
	private Store store;
	private List<CartItem> cartItems;

	public int getUserId() {
		return userId;
	}

	public void setUserId(int userId) {
		this.userId = userId;
	}

	public int getStoreId() {
		return storeId;
	}

	public void setStoreId(int storeId) {
		this.storeId = storeId;
	}

	public List<CartItem> getCartItem() {
		return cartItems;
	}

	public void setCartItem(List<CartItem> cartItem) {
		this.cartItems = cartItem;
	}

	public Store getStore() {
		return store;
	}

	public void setStore(Store store) {
		this.store = store;
	}

	public List<CartItem> getCartItems() {
		return cartItems;
	}

	public void setCartItems(List<CartItem> cartItems) {
		this.cartItems = cartItems;
	}
}
