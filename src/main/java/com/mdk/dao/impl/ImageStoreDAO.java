package com.mdk.dao.impl;

import com.mdk.connection.DBConnection;
import com.mdk.dao.IImageStoreDAO;
import com.mdk.models.ImageStore;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class ImageStoreDAO extends DBConnection implements IImageStoreDAO {
    Connection conn = null;
    PreparedStatement ps = null;
    ResultSet rs = null;
    @Override
    public void insert(ImageStore image) {
        String sql = "insert into image_store(name, storeId) values(?, ?)";
        try {
            conn = getConnection();
            ps = conn.prepareStatement(sql);
            ps.setString(1, image.getName());
            ps.setInt(2, image.getStoreId());
            ps.executeUpdate();
        }catch (SQLException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void delete(int storeId) {
        String sql = "delete from image_store where storeId = ?";
        try {
            conn = getConnection();
            ps = conn.prepareStatement(sql);
            ps.setInt(1, storeId);
            ps.executeUpdate();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    @Override
    public List<ImageStore> findByStoreId(int id) {
        String sql = "select * from image_store where storeId = ?";
        List<ImageStore> images = new ArrayList<>();
        try {
            conn = getConnection();
            ps = conn.prepareStatement(sql);
            ps.setInt(1, id);
            rs = ps.executeQuery();
            while (rs.next()) {
                ImageStore image = new ImageStore();
                image.setId(rs.getInt("id"));
                image.setName(rs.getString("name"));
                image.setStoreId(rs.getInt("storeId"));
                images.add(image);
            }
        }catch (SQLException e) {
            e.printStackTrace();
        }
        return images;
    }
}
