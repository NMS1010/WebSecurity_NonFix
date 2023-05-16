package com.mdk.dao.impl;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.mdk.connection.DBConnection;
import com.mdk.dao.IOrdersDAO;
import com.mdk.models.Delivery;
import com.mdk.models.OrderDetails;
import com.mdk.models.Orders;
import com.mdk.models.OrdersItem;
import com.mdk.models.Store;
import com.mdk.models.User;
import com.mdk.paging.Pageble;
import com.mdk.services.IDeliveryService;
import com.mdk.services.IOrdersItemService;
import com.mdk.services.IStoreService;
import com.mdk.services.IUserService;
import com.mdk.services.impl.DeliveryService;
import com.mdk.services.impl.OrdersItemService;
import com.mdk.services.impl.StoreService;
import com.mdk.services.impl.UserService;

public class OrdersDAO extends DBConnection implements IOrdersDAO {
    public Connection conn = null;
    public PreparedStatement ps = null;
    public ResultSet rs = null;
    


    public List<Orders> findAll(String status) {
        StringBuilder sql = new StringBuilder("select * from orders ");
        if (!status.equals("all")) {
            sql.append("where status like \"");
            sql.append(""+ status + "\"");
        }
        List<Orders> orders = new ArrayList<>();
        IUserService userService = new UserService();
        IStoreService storeService = new StoreService();
        IDeliveryService deliveryService = new DeliveryService();
        try {
            conn = getConnection();
            ps = conn.prepareStatement(String.valueOf(sql));
            rs = ps.executeQuery();
            while (rs.next()){
                Orders order = new Orders();
                User user = userService.findById(rs.getInt("userId"));
                Store store = storeService.findById(rs.getInt("storeId"));
                Delivery delivery = deliveryService.findById(rs.getInt("deliveryId"));
                order.setId(rs.getInt("id"));
                order.setUserId(rs.getInt("userId"));
                order.setStoreId(rs.getInt("storeId"));
                order.setDeliveryId(rs.getInt("deliveryId"));
                order.setAddress(rs.getString("address"));
                order.setPhone(rs.getString("phone"));
                order.setStatus(rs.getString("status"));
                order.setAmountFromUser(rs.getDouble("amountFromUser"));
                order.setAmountToStore(rs.getDouble("amountToStore"));
                order.setAmountToGD(rs.getDouble("amountToGD"));
                order.setCreatedAt(rs.getTimestamp("createdAt"));
                order.setUpdatedAt(rs.getTimestamp("updatedAt"));
                order.setUser(user);
                order.setStore(store);
                order.setDelivery(delivery);
                orders.add(order);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return orders;
    }
    @Override
    public Orders findById(int id) {
        StringBuilder sql = new StringBuilder("select * from orders where id = ?");
        try {
            conn = getConnection();
            ps = conn.prepareStatement(String.valueOf(sql));
            ps.setInt(1, id);
            rs = ps.executeQuery();
            Orders order = new Orders();
            IUserService userService = new UserService();
            IStoreService storeService = new StoreService();
            IDeliveryService deliveryService = new DeliveryService();
            IOrdersItemService ordersItemService = new OrdersItemService();
            while (rs.next()){
                User user = userService.findById(rs.getInt("userId"));
                Store store = storeService.findById(rs.getInt("storeId"));
                Delivery delivery = deliveryService.findById(rs.getInt("deliveryId"));
                List<OrdersItem> ordersItem = ordersItemService.findByOrdersId(rs.getInt("id"));
                order.setId(rs.getInt("id"));
                order.setAddress(rs.getString("address"));
                order.setPhone(rs.getString("phone"));
                order.setStatus(rs.getString("status"));
                order.setAmountFromUser(rs.getDouble("amountFromUser"));
                order.setAmountToStore(rs.getDouble("amountToStore"));
                order.setAmountToGD(rs.getDouble("amountToGD"));
                order.setCreatedAt(rs.getTimestamp("createdAt"));
                order.setUpdatedAt(rs.getTimestamp("updatedAt"));
                order.setUser(user);
                order.setStore(store);
                order.setDelivery(delivery);
                order.setOrdersItem(ordersItem);
            }
            return order;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }
    @Override
    public void updateStatus(String status, int id) {
        String sql = "update orders set status = ? where id = ?";
        try {
            conn = getConnection();
            ps = conn.prepareStatement(sql);
            ps.setString(1, status);
            ps.setInt(2, id);
            ps.executeUpdate();
        } catch (SQLException e){
            e.printStackTrace();
        }
    }
    @Override
    public List<OrderDetails> findDetailByOrderId(int id) {
        StringBuilder sql = new StringBuilder("select name, description, promotionalPrice, count "
                + "from product inner join ordersItem on product.id = ordersItem.productId "
                + "where ordersItem.ordersId = ?");
        try {
            conn = getConnection();
            ps = conn.prepareStatement(String.valueOf(sql));
            ps.setInt(1, id);
            rs = ps.executeQuery();
            List<OrderDetails> orderDetails = new ArrayList<>();
            while (rs.next()){
                OrderDetails orderDetail = new OrderDetails();
                orderDetail.setName(rs.getString("name"));
                orderDetail.setDescription(rs.getString("description"));
                orderDetail.setPrice(rs.getDouble("promotionalPrice"));
                orderDetail.setCount(rs.getInt("count"));
                orderDetails.add(orderDetail);
            }
            return orderDetails;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }
    @Override
    public Orders findOneById(int id) {
        String sql = "SELECT * FROM orders WHERE id = ?";
        try {
            conn = super.getConnection();
            ps = conn.prepareStatement(sql);
            ps.setInt(1, id);
            rs = ps.executeQuery();
            while(rs.next()) {
                Orders order = new Orders();
                order.setId(rs.getInt("id"));
                order.setUserId(rs.getInt("userId"));
                order.setStoreId(rs.getInt("storeId"));
                order.setDeliveryId(rs.getInt("deliveryId"));
                order.setAddress(rs.getString("address"));
                order.setStatus(rs.getString("status"));
                order.setPhone(rs.getString("phone"));
                order.setAmountFromUser(rs.getDouble("amountFromUser"));
                order.setAmountToStore(rs.getDouble("amountToStore"));
                order.setAmountToGD(rs.getDouble("amountToGD"));
                return  order;
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
    @Override
    public int count(String status, int storeId, String start, String end) {
        StringBuilder sql = new StringBuilder("select count(*) from orders");
        if (!status.equals("all")) {
            sql.append(" where status like \"");
            sql.append(""+ status + "\"");
            sql.append(" and storeId = " + storeId);
        } else {
            sql.append(" where storeId = " + storeId);
        }
        if (start != null && end != null) {
            sql.append(" and createdAt between " + "\"" + start + "\"" + " and " + "\"" + end + "\"");
        }
        try {
            conn = getConnection();
            ps = conn.prepareStatement(String.valueOf(sql));
            rs = ps.executeQuery();
            while (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return 0;
    }
    @Override
    public List<Orders> findAll(String status, Pageble pageble, int storeId, String start, String end) {
        StringBuilder sql = new StringBuilder("select * from orders");
        if (!status.equals("all")) {
            sql.append(" where status like \"");
            sql.append(""+ status + "\"");
            sql.append(" and storeId = " + storeId);
        } else {
            sql.append(" where storeId = " + storeId);
        }
        if (start != null && end != null) {
            sql.append(" and createdAt between " + "\"" + start + "\"" + " and " + "\"" + end + "\"");
        }
        if (pageble.getSorter() != null) {
            sql.append(" order by "+pageble.getSorter().getSortName()+" "+pageble.getSorter().getSortBy()+"");
        }
        if (pageble.getOffset() != null && pageble.getLimit() != null) {
            sql.append(" limit "+pageble.getOffset()+", "+pageble.getLimit()+"");
        }
        List<Orders> orders = new ArrayList<>();
        IUserService userService = new UserService();
        IStoreService storeService = new StoreService();
        IDeliveryService deliveryService = new DeliveryService();
        try {
            conn = getConnection();
            ps = conn.prepareStatement(String.valueOf(sql));
            rs = ps.executeQuery();
            while (rs.next()){
                Orders order = new Orders();
                User user = userService.findById(rs.getInt("userId"));
                Store store = storeService.findById(rs.getInt("storeId"));
                Delivery delivery = deliveryService.findById(rs.getInt("deliveryId"));
                order.setId(rs.getInt("id"));
                order.setUserId(rs.getInt("userId"));
                order.setStoreId(rs.getInt("storeId"));
                order.setDeliveryId(rs.getInt("deliveryId"));
                order.setAddress(rs.getString("address"));
                order.setPhone(rs.getString("phone"));
                order.setStatus(rs.getString("status"));
                order.setAmountFromUser(rs.getDouble("amountFromUser"));
                order.setAmountToStore(rs.getDouble("amountToStore"));
                order.setAmountToGD(rs.getDouble("amountToGD"));
                order.setCreatedAt(rs.getTimestamp("createdAt"));
                order.setUpdatedAt(rs.getTimestamp("updatedAt"));
                order.setUser(user);
                order.setStore(store);
                order.setDelivery(delivery);
                orders.add(order);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return orders;
    }

    @Override
    public int countByStoreId(String status, int storeId, String keyword) {
        StringBuilder sql = new StringBuilder("select count(*) from orders inner join user on orders.userId = user.id");
        if (!status.equals("all")) {
            sql.append(" where status like \"");
            sql.append(""+ status + "\" and storeId = " + storeId);
        }
        if (keyword != null) {
            sql.append(" and (user.lastname like ");
            sql.append("\"%" + keyword + "%\" or user.firstname like ");
            sql.append("\"%" + keyword + "%\")");
        }
        try {
            conn = getConnection();
            ps = conn.prepareStatement(String.valueOf(sql));
            rs = ps.executeQuery();
            while (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return 0;
    }

    @Override
    public List<Orders> findAllByStoreId(String status, int storeId, Pageble pageble, String keyword) {
        StringBuilder sql = new StringBuilder("select * from orders inner join user on orders.userId = user.id");
        if (!status.equals("all")) {
            sql.append(" where status like \"");
            sql.append(""+ status + "\"" + " and storeId = "+ storeId);
        }
        if (keyword != null) {
            sql.append(" and (user.lastname like ");
            sql.append("\"%" + keyword + "%\" or user.firstname like ");
            sql.append("\"%" + keyword + "%\")");
        }
        if (pageble.getSorter() != null) {
            sql.append(" order by "+pageble.getSorter().getSortName()+" "+pageble.getSorter().getSortBy()+"");
        }
        if (pageble.getOffset() != null && pageble.getLimit() != null) {
            sql.append(" limit "+pageble.getOffset()+", "+pageble.getLimit()+"");
        }
        List<Orders> orders = new ArrayList<>();
        IUserService userService = new UserService();
        IStoreService storeService = new StoreService();
        IDeliveryService deliveryService = new DeliveryService();
        try {
            conn = getConnection();
            ps = conn.prepareStatement(String.valueOf(sql));
            rs = ps.executeQuery();
            while (rs.next()){
                Orders order = new Orders();
                User user = userService.findById(rs.getInt("userId"));
                Store store = storeService.findById(rs.getInt("storeId"));
                Delivery delivery = deliveryService.findById(rs.getInt("deliveryId"));
                order.setId(rs.getInt("id"));
                order.setUserId(rs.getInt("userId"));
                order.setStoreId(rs.getInt("storeId"));
                order.setDeliveryId(rs.getInt("deliveryId"));
                order.setAddress(rs.getString("address"));
                order.setPhone(rs.getString("phone"));
                order.setStatus(rs.getString("status"));
                order.setAmountFromUser(rs.getDouble("amountFromUser"));
                order.setAmountToStore(rs.getDouble("amountToStore"));
                order.setAmountToGD(rs.getDouble("amountToGD"));
                order.setCreatedAt(rs.getTimestamp("createdAt"));
                order.setUpdatedAt(rs.getTimestamp("updatedAt"));
                order.setUser(user);
                order.setStore(store);
                order.setDelivery(delivery);
                orders.add(order);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return orders;
    }
	@Override
	public int currentIndex() {
		StringBuilder sql = new StringBuilder("SELECT MAX(id) FROM orders;");
        try {
            conn = getConnection();
            ps = conn.prepareStatement(String.valueOf(sql));
            rs = ps.executeQuery();
            while (rs.next()) {
                return rs.getInt(1);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return 0;
	}
	@Override
	public void insert(Orders order) {
		String sql = "INSERT INTO orders (userId, storeId, deliveryId, address, phone, amountFromUser, amountToStore, amountToGD) "
				+ "VALUE (?,?,?,?,?,?,?,?)";
        try {
            conn = getConnection();
            ps = conn.prepareStatement(sql);
            ps.setInt(1, order.getUserId());
            ps.setInt(2, order.getStoreId());
            ps.setInt(3, order.getDeliveryId());
            ps.setString(4, order.getAddress());
            ps.setString(5, order.getPhone());
            ps.setDouble(6, order.getAmountFromUser());
            ps.setDouble(7, order.getAmountToStore());
            ps.setDouble(8, order.getAmountToGD());
            ps.executeUpdate();
        } catch (SQLException e){
            e.printStackTrace();
        }
	}

    @Override
    public List<Orders> ordersNew(int storeId) {
        String sql = "select * from orders where storeId = ? and status like \"not-processed\" order by createdAt " +
                "DESC limit 4";
        List<Orders> orders = new ArrayList<>();
        IUserService userService = new UserService();
        IStoreService storeService = new StoreService();
        IDeliveryService deliveryService = new DeliveryService();
        
        try {
            conn = getConnection();
            ps = conn.prepareStatement(sql);
            ps.setInt(1, storeId);
            rs = ps.executeQuery();
            while (rs.next()){
                Orders order = new Orders();
                User user = userService.findById(rs.getInt("userId"));
                Store store = storeService.findById(rs.getInt("storeId"));
                Delivery delivery = deliveryService.findById(rs.getInt("deliveryId"));
                order.setId(rs.getInt("id"));
                order.setUserId(rs.getInt("userId"));
                order.setStoreId(rs.getInt("storeId"));
                order.setDeliveryId(rs.getInt("deliveryId"));
                order.setAddress(rs.getString("address"));
                order.setPhone(rs.getString("phone"));
                order.setStatus(rs.getString("status"));
                order.setAmountFromUser(rs.getDouble("amountFromUser"));
                order.setAmountToStore(rs.getDouble("amountToStore"));
                order.setAmountToGD(rs.getDouble("amountToGD"));
                order.setCreatedAt(rs.getTimestamp("createdAt"));
                order.setUpdatedAt(rs.getTimestamp("updatedAt"));
                order.setUser(user);
                order.setStore(store);
                order.setDelivery(delivery);
                orders.add(order);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return orders;
    }
	@Override
	public List<Orders> findAllByUser(int userId) {
		String sql = "select * from orders where userId = ? order by createdAt desc";
        List<Orders> orders = new ArrayList<>();
        IUserService userService = new UserService();
        IStoreService storeService = new StoreService();
        IDeliveryService deliveryService = new DeliveryService();
        IOrdersItemService ordersItemService = new OrdersItemService();
        try {
            conn = getConnection();
            ps = conn.prepareStatement(sql);
            ps.setInt(1, userId);
            rs = ps.executeQuery();
            while (rs.next()){
                Orders order = new Orders();
                User user = userService.findById(rs.getInt("userId"));
                Store store = storeService.findById(rs.getInt("storeId"));
                Delivery delivery = deliveryService.findById(rs.getInt("deliveryId"));
                List<OrdersItem> ordersItem = ordersItemService.findByOrdersId(rs.getInt("id"));
                order.setId(rs.getInt("id"));
                order.setUserId(rs.getInt("userId"));
                order.setStoreId(rs.getInt("storeId"));
                order.setDeliveryId(rs.getInt("deliveryId"));
                order.setAddress(rs.getString("address"));
                order.setPhone(rs.getString("phone"));
                order.setStatus(rs.getString("status"));
                order.setAmountFromUser(rs.getDouble("amountFromUser"));
                order.setAmountToStore(rs.getDouble("amountToStore"));
                order.setAmountToGD(rs.getDouble("amountToGD"));
                order.setCreatedAt(rs.getTimestamp("createdAt"));
                order.setUpdatedAt(rs.getTimestamp("updatedAt"));
                order.setUser(user);
                order.setStore(store);
                order.setDelivery(delivery);
                order.setOrdersItem(ordersItem);
                orders.add(order);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return orders;
	}

    @Override
    public List<Orders> findAllForReport() {
        StringBuilder sql = new StringBuilder("select * from orders where status = 'delivered'");
        List<Orders> orders = new ArrayList<>();
        IUserService userService = new UserService();
        IDeliveryService deliveryService = new DeliveryService();
        try {
            conn = getConnection();
            ps = conn.prepareStatement(String.valueOf(sql));
            rs = ps.executeQuery();
            while (rs.next()){
                Orders order = new Orders();
                User user = userService.findById(rs.getInt("userId"));
                Delivery delivery = deliveryService.findById(rs.getInt("deliveryId"));
                order.setNameOwner(user.getLastname() + " " + user.getFirstname());
                order.setNameDelivery(delivery.getName());
                order.setAddress(rs.getString("address"));
                order.setPhone(rs.getString("phone"));
                order.setAmountFromUser(rs.getDouble("amountFromUser"));
                orders.add(order);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return orders;
    }

}
