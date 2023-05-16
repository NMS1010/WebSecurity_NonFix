package com.mdk.dao.impl;

import com.mdk.connection.DBConnection;
import com.mdk.dao.IReportOrderDAO;
import com.mdk.models.ReportOrder;
import com.mdk.services.ICategoryService;
import com.mdk.services.impl.CategoryService;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class ReportOrderDAO extends DBConnection implements IReportOrderDAO {
    public Connection conn = null;
    public PreparedStatement ps = null;
    public ResultSet rs = null;
    @Override
    public List<ReportOrder> getReportOrder(int storeId, String status, String dateStart, String dateEnd) {
        StringBuilder sql = new StringBuilder("select o.id orderId, oi.id orderItemId, o.createdAt dateorder, o.status, d.id deliveryId, d.name deliveryname, p.categoryId categoryId,\n" +
                "p.name productname, p.price, p.promotionalPrice, oi.count , d.price pricedelivery,  u.lastname, u.firstname , o.phone, o.address\n" +
                "from orders o \n" +
                "inner join ordersItem oi on o.id = oi.ordersId\n" +
                "inner join delivery d on d.id = deliveryId\n" +
                "inner join product p on p.id = productId\n" +
                "inner join user u on u.id = userId\n" +
                "inner join store st on st.id = o.storeId");
        sql.append(" where st.id = " + storeId);
        if (!status.equals("all")) {
            sql.append(" and o.status like \"");
            sql.append(""+ status + "\"");
        }
        sql.append(" and o.createdAt between " + "\"" + dateStart + "\"" + " and " + "\"" + dateEnd + "\"");
        List<ReportOrder> reportOrders = new ArrayList<>();
        ICategoryService categoryService = new CategoryService();
        try {
            conn = getConnection();
            ps = conn.prepareStatement(String.valueOf(sql));
            rs = ps.executeQuery();
            while (rs.next()) {
                ReportOrder reportOrder = new ReportOrder();
                reportOrder.setOrderId(rs.getInt("orderId"));
                reportOrder.setOrderItemId(rs.getInt("orderItemId"));
                reportOrder.setDateOrder(rs.getTimestamp("dateorder"));
                reportOrder.setStatus(rs.getString("status"));
                reportOrder.setDeliveryId(rs.getInt("deliveryId"));
                reportOrder.setDeliveryName(rs.getString("deliveryname"));
                reportOrder.setCategoryName(categoryService.findById(rs.getInt("categoryId")).getName());
                reportOrder.setProductName(rs.getString("productname"));
                reportOrder.setPrice(rs.getDouble("price"));
                reportOrder.setPromotionalPrice(rs.getDouble("promotionalPrice"));
                reportOrder.setCount(rs.getInt("count"));
                reportOrder.setPriceDelivery(rs.getDouble("pricedelivery"));
                reportOrder.setUserOrder(rs.getString("firstname")+ " " + rs.getString("lastname"));
                reportOrder.setPhone(rs.getString("phone"));
                reportOrder.setAddress(rs.getString("address"));
                reportOrders.add(reportOrder);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return reportOrders;
    }
}
