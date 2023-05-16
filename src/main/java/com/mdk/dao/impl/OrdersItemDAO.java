package com.mdk.dao.impl;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.mdk.connection.DBConnection;
import com.mdk.dao.IOrdersItemDAO;
import com.mdk.models.OrdersItem;
import com.mdk.services.IOrdersService;
import com.mdk.services.IProductService;
import com.mdk.services.impl.OrdersService;
import com.mdk.services.impl.ProductService;

public class OrdersItemDAO extends DBConnection implements IOrdersItemDAO {
	public Connection conn = null;
	public PreparedStatement ps = null;
	public ResultSet rs = null;

	@Override
	public void insert(OrdersItem orderItem) {
		String sql = "INSERT INTO OrdersItem (ordersId, productId, count) " + "VALUE (?,?,?)";
		try {
			conn = getConnection();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, orderItem.getOrdersId());
			ps.setInt(2, orderItem.getProductId());
			ps.setInt(3, orderItem.getCount());
			ps.executeUpdate();
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}

	@Override
	public List<OrdersItem> findByOrdersId(int ordersId) {
		String sql = "select * from ordersItem where ordersId = ?";
		List<OrdersItem> ordersItems = new ArrayList<>();
		IOrdersService ordersService = new OrdersService();
		IProductService productService = new ProductService();
		try {
			conn = getConnection();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, ordersId);
			rs = ps.executeQuery();
			while (rs.next()) {
				OrdersItem ordersItem = new OrdersItem();
				ordersItem.setId(rs.getInt("id"));
				ordersItem.setOrdersId(rs.getInt("ordersId"));
				ordersItem.setProductId(rs.getInt("productId"));
				ordersItem.setCount(rs.getInt("count"));
				ordersItem.setProduct(productService.findOneById(rs.getInt("productId")));
				ordersItems.add(ordersItem);
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return ordersItems;
	}
}
