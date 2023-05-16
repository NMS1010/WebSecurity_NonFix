package com.mdk.dao.impl;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.mdk.connection.DBConnection;
import com.mdk.dao.IDeliveryDAO;
import com.mdk.models.Delivery;
import com.mdk.paging.Pageble;

public class DeliveryDAO extends DBConnection implements IDeliveryDAO {
    public Connection conn = null;
    public PreparedStatement ps = null;
    public ResultSet rs = null;

    @Override
    public Delivery findById(int id) {
        String sql = "select * from delivery where id = ?";
        Delivery delivery = new Delivery();
        try {
            conn = getConnection();
            ps = conn.prepareStatement(sql);
            ps.setInt(1, id);
            rs = ps.executeQuery();
            while (rs.next()) {
                delivery.setId(rs.getInt("id"));
                delivery.setName(rs.getString("name"));
                delivery.setDescription(rs.getString("description"));
                delivery.setPrice(rs.getDouble("price"));
                delivery.setDeleted(rs.getBoolean("isDeleted"));
                delivery.setCreatedAt(rs.getTimestamp("createdAt"));
                delivery.setUpdatedAt(rs.getTimestamp("updatedAt"));
            }
            return delivery;
        } catch (SQLException e){
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public int count(String state, String keyword) {
        StringBuilder sql = new StringBuilder("select count(*) from delivery");
        if(state != "") {
            sql.append(" where isDeleted = " + state);
        }
        if (keyword != null) {
            sql.append(" and name like ");
            sql.append("\"%" + keyword + "%\"");
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
    public List<Delivery> findAll(Pageble pageble, String state, String keyword) {
        StringBuilder sql = new StringBuilder("select * from delivery");
        if (state != "") {
            sql.append(" where isDeleted = " + state);
        }
        if (keyword != null) {
            sql.append(" and name like ");
            sql.append("\"%" + keyword + "%\"");
        }
        if (pageble.getSorter() != null) {
            sql.append(" order by " + pageble.getSorter().getSortName() + " " + pageble.getSorter().getSortBy() + "");
        }
        if (pageble.getOffset() != null && pageble.getLimit() != null) {
            sql.append(" limit " + pageble.getOffset() + ", " + pageble.getLimit() + "");
        }
        List<Delivery> deliveries = new ArrayList<>();
        try {
            conn = getConnection();
            ps = conn.prepareStatement(String.valueOf(sql));
            rs = ps.executeQuery();
            while (rs.next()) {
                Delivery delivery = new Delivery();
                delivery.setId(rs.getInt("id"));
                delivery.setName(rs.getString("name"));
                delivery.setDescription(rs.getString("description"));
                delivery.setPrice(rs.getDouble("price"));
                delivery.setDeleted(rs.getBoolean("isDeleted"));
                deliveries.add(delivery);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return deliveries;

    }

    @Override
    public List<Delivery> findAllActive() {
        String sql = "SELECT * FROM delivery where isDeleted = 0";
        List<Delivery> deliveries = new ArrayList<Delivery>();
        try {
            conn = super.getConnection();
            ps = conn.prepareStatement(sql);
            rs = ps.executeQuery();
            while(rs.next()) {
                Delivery delivery = new Delivery();
                delivery.setId(rs.getInt("id"));
                delivery.setName(rs.getString("name"));
                delivery.setDescription(rs.getString("description"));
                delivery.setPrice(rs.getDouble("price"));
                delivery.setDeleted(rs.getBoolean("isDeleted"));
                deliveries.add(delivery);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return deliveries;
    }

    @Override
    public void insert(Delivery delivery) {
        String sql = "INSERT INTO delivery(name, description, price) VALUES (?,?,?)";
        try {
            conn = super.getConnection();
            ps = conn.prepareStatement(sql);
            ps.setString(1, delivery.getName());
            ps.setString(2, delivery.getDescription());
            ps.setDouble(3, delivery.getPrice());
            ps.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void edit(Delivery delivery) {
        String sql = "UPDATE delivery SET name = ?, description = ?, price = ? WHERE id = ?";
        try {
            conn = super.getConnection();
            ps = conn.prepareStatement(sql);
            ps.setString(1, delivery.getName());
            ps.setString(2, delivery.getDescription());
            ps.setDouble(3, delivery.getPrice());
            ps.setInt(4, delivery.getId());
            ps.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void deleteSoft(int id) {
        String sql = "UPDATE delivery SET isDeleted = true WHERE id = ?";
        try {
            conn = super.getConnection();
            ps = conn.prepareStatement(sql);
            ps.setInt(1, id);
            ps.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void delete(int id) {
        String sql = "DELETE FROM delivery WHERE id = ?";
        try {
            conn = super.getConnection();
            ps = conn.prepareStatement(sql);
            ps.setInt(1, id);
            ps.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void restore(int id) {
        String sql = "UPDATE delivery SET isDeleted = false WHERE id = ?";
        try {
            conn = super.getConnection();
            ps = conn.prepareStatement(sql);
            ps.setInt(1, id);
            ps.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void updateStatus(Delivery delivery) {

    }
}