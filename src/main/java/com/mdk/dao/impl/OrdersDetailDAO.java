package com.mdk.dao.impl;

import com.mdk.connection.DBConnection;
import com.mdk.dao.IOrdersDetailDAO;
import com.mdk.models.Orders;
import com.mdk.models.OrdersDetail;
import com.mdk.models.Product;
import com.mdk.models.ProductOfOrder;
import com.mdk.services.IOrdersService;
import com.mdk.services.IProductService;
import com.mdk.services.impl.OrdersService;
import com.mdk.services.impl.ProductService;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class OrdersDetailDAO extends DBConnection implements IOrdersDetailDAO {
    public Connection conn = null;
    public PreparedStatement ps = null;
    public ResultSet rs = null;
    @Override
    public OrdersDetail findOrderDetailById(int id) {
        IOrdersService ordersService = new OrdersService();
        IProductService productService = new ProductService();
        List<ProductOfOrder> productOfOrderList = new ArrayList<>();
        OrdersDetail ordersDetail = new OrdersDetail();
        Orders orders = ordersService.findById(id);
        String sql = "select oi.productId, oi.count from orders inner join ordersItem oi on orders.id = ordersId " +
                "where orders.id = ?";
        try {
            conn = getConnection();
            ps = conn.prepareStatement(sql);
            ps.setInt(1, id);
            rs = ps.executeQuery();
            while (rs.next()) {
                ProductOfOrder productOfOrder = new ProductOfOrder();
                Product product = productService.findOneById(rs.getInt("productId"));
                productOfOrder.setProductId(product.getId());
                productOfOrder.setName(product.getName());
                productOfOrder.setPrice(product.getPromotionalPrice());
                productOfOrder.setCount(rs.getInt("count"));
                productOfOrderList.add(productOfOrder);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        ordersDetail.setOrdersId(orders.getId());
        ordersDetail.setUserName(orders.getUser().getFirstname() + " " +orders.getUser().getLastname());
        ordersDetail.setStoreName(orders.getStore().getName());
        ordersDetail.setPhone(orders.getPhone());
        ordersDetail.setAddress(orders.getAddress());
        ordersDetail.setDeliveryName(orders.getDelivery().getName());
        ordersDetail.setCreatedAt(orders.getCreatedAt());
        ordersDetail.setStatus(orders.getStatus());
        ordersDetail.setProducts(productOfOrderList);
        return ordersDetail;
    }
}
