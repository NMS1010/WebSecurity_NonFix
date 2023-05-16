package com.mdk.dao.impl;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

import com.mdk.connection.DBConnection;
import com.mdk.dao.ICartItemDAO;
import com.mdk.models.CartItem;
import com.mdk.services.IProductService;
import com.mdk.services.impl.ProductService;

public class CartItemDAO extends DBConnection implements ICartItemDAO {
	public Connection conn = null;
	public PreparedStatement ps = null;
	public ResultSet rs = null;
	

	@Override
	public void insert(CartItem cartItem) {
		String sql = "INSERT INTO cartItem (cartId, productId, count)" + "VALUES (?,?,?)";
		try {
			conn = super.getConnection();
			ps = conn.prepareStatement(sql);
			ps.setLong(1, cartItem.getCartId());
			ps.setLong(2, cartItem.getProductId());
			ps.setLong(3, cartItem.getCount());
			ps.executeUpdate();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void update(CartItem cartItem) {
		String sql = "UPDATE cartItem " + "SET cartId = ?, productId = ?, count = ? " + "WHERE id = ?";
		try {
			conn = super.getConnection();
			ps = conn.prepareStatement(sql);
			ps.setLong(1, cartItem.getCartId());
			ps.setLong(2, cartItem.getProductId());
			ps.setLong(3, cartItem.getCount());
			ps.setLong(4, cartItem.getId());
			ps.executeUpdate();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void delete(int id) {
		String sql = "DELETE FROM cartItem WHERE id = ?";
		try {
			conn = super.getConnection();
			ps = conn.prepareStatement(sql);
			ps.setLong(1, id);
			ps.executeUpdate();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public List<CartItem> findAllByCart(int cartId) {
		String sql = "SELECT * FROM CartItem WHERE cartId = ?";
		List<CartItem> cartItems = new ArrayList<CartItem>();
		IProductService productService = new ProductService();
		try {
			conn = super.getConnection();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, cartId);
			rs = ps.executeQuery();
			while (rs.next()) {
				CartItem cartItem = new CartItem();
				cartItem.setId(rs.getInt("id"));
				cartItem.setCartId(rs.getInt("cartId"));
				cartItem.setProductId(rs.getInt("productId"));
				cartItem.setCount(rs.getInt("count"));
				cartItem.setProduct(productService.findOneById(cartItem.getProductId()));
				cartItems.add(cartItem);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return cartItems;
	}

	@Override
	public CartItem findOneById(int id) {
		String sql = "SELECT * FROM cartItem WHERE id = ?";
		IProductService productService = new ProductService();
		try {
			conn = super.getConnection();
			ps = conn.prepareStatement(sql);
			ps.setLong(1, id);
			rs = ps.executeQuery();
			while (rs.next()) {
				CartItem cartItem = new CartItem();
				cartItem.setId(rs.getInt("id"));
				cartItem.setCartId(rs.getInt("cartId"));
				cartItem.setProductId(rs.getInt("productId"));
				cartItem.setCount(rs.getInt("count"));
				cartItem.setProduct(productService.findOneById(cartItem.getProductId()));
				return cartItem;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public CartItem findByCartAndProduct(int cartId, int productId) {
		String sql = "SELECT * FROM cartItem WHERE cartId = ? AND productId = ?";
		try {
			conn = super.getConnection();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, cartId);
			ps.setInt(2, productId);
			rs = ps.executeQuery();
			while (rs.next()) {
				CartItem cartItem = new CartItem();
				cartItem.setId(rs.getInt("id"));
				cartItem.setCartId(rs.getInt("cartId"));
				cartItem.setProductId(rs.getInt("productId"));
				cartItem.setCount(rs.getInt("count"));
				return cartItem;
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
}
