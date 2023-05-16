package com.mdk.dao.impl;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.mdk.connection.DBConnection;
import com.mdk.dao.IImageProductDAO;
import com.mdk.models.ImageProduct;

public class ImageProductDAO extends DBConnection implements IImageProductDAO {
    Connection conn = null;
    PreparedStatement ps = null;
    ResultSet rs = null;
    @Override
    public void insert(ImageProduct image) {
        String sql = "insert into image_product(name, productId) values(?, ?)";
        try {
            conn = getConnection();
            ps = conn.prepareStatement(sql);
            ps.setString(1, image.getName());
            ps.setInt(2, image.getProductId());
            ps.executeUpdate();
        }catch (SQLException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void delete(int productId) {
        StringBuilder sql = new StringBuilder("delete from image_product where productId = ?");
        try {
            conn = getConnection();
            ps = conn.prepareStatement(String.valueOf(sql));
            ps.setInt(1, productId);
            ps.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    @Override
    public List<ImageProduct> findByProductId(int id) {
        String sql = "select * from image_product where productId = ?";
        List<ImageProduct> images = new ArrayList<>();
        try {
            conn = getConnection();
            ps = conn.prepareStatement(sql);
            ps.setInt(1, id);
            rs = ps.executeQuery();
            while (rs.next()) {
                ImageProduct image = new ImageProduct();
                image.setId(rs.getInt("id"));
                image.setName(rs.getString("name"));
                image.setProductId(rs.getInt("productId"));
                images.add(image);
            }
        }catch (SQLException e) {
            e.printStackTrace();
        }
        return images;
    }
}
