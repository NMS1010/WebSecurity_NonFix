package com.mdk.dao.impl;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

import com.mdk.connection.DBConnection;
import com.mdk.dao.ICartDAO;
import com.mdk.models.Cart;
import com.mdk.services.ICartItemService;
import com.mdk.services.IStoreService;
import com.mdk.services.impl.CartItemService;
import com.mdk.services.impl.StoreService;

public class CartDAO extends DBConnection implements ICartDAO {

	public Connection conn = null;
	public PreparedStatement ps = null;
	public ResultSet rs = null;
	

	@Override
	public void insert(Cart cart) {
		String sql = "INSERT INTO cart (userId, storeId)" + "VALUES (?,?)";
		try {
			conn = super.getConnection();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, cart.getUserId());
			ps.setInt(2, cart.getStoreId());
			ps.executeUpdate();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	@Override
	public void update(Cart cart) {
		String sql = "UPDATE cart " + "SET userId = ?, storeId = ?" + "WHERE id = ?";
		try {
			conn = super.getConnection();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, cart.getUserId());
			ps.setInt(2, cart.getStoreId());
			ps.setInt(3, cart.getId());
			ps.executeUpdate();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void delete(int id) {
		String sql = "DELETE FROM cart WHERE id = ?";
		try {
			Connection con = super.getConnection();
			PreparedStatement ps = con.prepareStatement(sql);
			ps.setInt(1, id);
			ps.executeUpdate();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public List<Cart> findAll() {
		String sql = "SELECT * FROM cart";
		List<Cart> carts = new ArrayList<Cart>();
		try {
			Connection getConnection = super.getConnection();
			PreparedStatement pStatement = getConnection.prepareStatement(sql);
			ResultSet resultSet = pStatement.executeQuery();
			while (resultSet.next()) {
				Cart cart = new Cart();
				cart.setUserId(resultSet.getInt("userId"));
				cart.setStoreId(resultSet.getInt("storeId"));
				carts.add(cart);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return carts;
	}

	@Override
	public Cart findById(int id) {
		String sql = "SELECT * FROM cart WHERE id = ?";
		ICartItemService cartItemService = new CartItemService();
		IStoreService storeService = new StoreService();
		try {
			Connection getConnection = super.getConnection();
			PreparedStatement pStatement = getConnection.prepareStatement(sql);
			pStatement.setLong(1, id);
			ResultSet resultSet = pStatement.executeQuery();
			while (resultSet.next()) {
				Cart cart = new Cart();
				cart.setId(resultSet.getInt("id"));
				cart.setUserId(resultSet.getInt("userId"));
				cart.setStoreId(resultSet.getInt("storeId"));
				cart.setStore(storeService.findById(cart.getStoreId()));
				cart.setCartItem(cartItemService.findAllByCart(cart.getId()));
				return cart;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public List<Cart> findByUserId(int userId) {
		String sql = "SELECT DISTINCT Cart.* FROM Cart INNER JOIN CartItem ON Cart.id = CartItem.cartId WHERE Cart.userId = ?";
		List<Cart> carts = new ArrayList<Cart>();
		ICartItemService cartItemService = new CartItemService();
		IStoreService storeService = new StoreService();
		try {
			Connection getConnection = super.getConnection();
			PreparedStatement pStatement = getConnection.prepareStatement(sql);
			pStatement.setInt(1, userId);
			ResultSet resultSet = pStatement.executeQuery();
			while (resultSet.next()) {
				Cart cart = new Cart();
				cart.setId(resultSet.getInt("id"));
				cart.setUserId(resultSet.getInt("userId"));
				cart.setStoreId(resultSet.getInt("storeId"));
				cart.setStore(storeService.findById(cart.getStoreId()));
				cart.setCartItem(cartItemService.findAllByCart(cart.getId()));
				carts.add(cart);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return carts;
	}

	@Override
	public Cart findByUserAndStore(int userId, int storeId) {
		String sql = "SELECT * FROM cart WHERE userId = ? AND storeId = ?";
		try {
			Connection getConnection = super.getConnection();
			PreparedStatement pStatement = getConnection.prepareStatement(sql);
			pStatement.setLong(1, userId);
			pStatement.setLong(2, storeId);
			ResultSet resultSet = pStatement.executeQuery();
			while (resultSet.next()) {
				Cart cart = new Cart();
				cart.setId(resultSet.getInt("id"));
				cart.setUserId(resultSet.getInt("userId"));
				cart.setStoreId(resultSet.getInt("storeId"));
				return cart;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

}
