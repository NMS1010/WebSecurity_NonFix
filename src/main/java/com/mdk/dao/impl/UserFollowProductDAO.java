package com.mdk.dao.impl;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.mdk.connection.DBConnection;
import com.mdk.dao.IUserFollowProductDAO;
import com.mdk.models.UserFollowProduct;
import com.mdk.services.IProductService;
import com.mdk.services.IUserService;
import com.mdk.services.impl.ProductService;
import com.mdk.services.impl.UserService;


public class UserFollowProductDAO extends DBConnection implements IUserFollowProductDAO {

	public Connection conn = null;
	public PreparedStatement ps = null;
	public ResultSet rs = null;
	

	@Override
	public void insert(UserFollowProduct userFollowProduct) {
		String sql = "insert into userfollowproduct(userId, productId) values(?, ?)";
		try {
			conn = getConnection();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, userFollowProduct.getUserId());
			ps.setInt(2, userFollowProduct.getProductId());
			ps.executeUpdate();
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void delete(int id) {
		String sql = "delete from userfollowproduct where id = ?";
		try {
			conn = getConnection();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, id);
			ps.executeUpdate();
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}

	@Override
	public List<UserFollowProduct> findByUserId(int id) {
		String sql = "select * from userfollowproduct where userId = ?";
		List<UserFollowProduct> userFollowProducts = new ArrayList<UserFollowProduct>();
		IUserService userService = new UserService();
		IProductService productService = new ProductService();
		try {
			conn = getConnection();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, id);
			rs = ps.executeQuery();
			while (rs.next()) {
				UserFollowProduct userFollowProduct = new UserFollowProduct();
				userFollowProduct.setId(rs.getInt("id"));
				userFollowProduct.setUserId(rs.getInt("userId"));
				userFollowProduct.setProductId(rs.getInt("productId"));
				userFollowProduct.setProduct(productService.findOneById(userFollowProduct.getProductId()));
				userFollowProduct.setUser(userService.findById(userFollowProduct.getUserId()));
				userFollowProducts.add(userFollowProduct);
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return userFollowProducts;
	}
	
	public UserFollowProduct findFollow(UserFollowProduct userFollowProduct){
		String sql = "select * from userfollowproduct where userId = ? AND productId = ?";
		IUserService userService = new UserService();
		IProductService productService = new ProductService();
		try {
			conn = getConnection();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, userFollowProduct.getUserId());
			ps.setInt(2, userFollowProduct.getProductId());
			
			rs = ps.executeQuery();
			while (rs.next()) {
				UserFollowProduct new_userFollowProduct = new UserFollowProduct();
				new_userFollowProduct.setId(rs.getInt("id"));
				new_userFollowProduct.setUserId(rs.getInt("userId"));
				new_userFollowProduct.setProductId(rs.getInt("productId"));
				new_userFollowProduct.setProduct(productService.findOneById(userFollowProduct.getProductId()));
				new_userFollowProduct.setUser(userService.findById(userFollowProduct.getUserId()));
				return new_userFollowProduct;
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return null;
		
	}

	@Override
	public void update(UserFollowProduct userFollowProduct) {
		String sql = "update userfollowproduct "
				+ "set userId = ?, productId = ? "
				+ "where id = ?";
		try {
			conn = getConnection();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, userFollowProduct.getUserId());
			ps.setInt(2, userFollowProduct.getProductId());
			ps.setInt(3, userFollowProduct.getId());
			ps.executeUpdate();
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}

}
