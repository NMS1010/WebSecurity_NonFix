package com.mdk.dao.impl;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.mdk.connection.DBConnection;
import com.mdk.dao.ICategoryDAO;
import com.mdk.models.Category;
import com.mdk.paging.Pageble;

public class CategoryDAO extends DBConnection implements ICategoryDAO {
    public Connection conn = null;
    public PreparedStatement ps = null;
    public ResultSet rs = null;

    @Override
    public Category findById(int id) {
        String sql =  "select * from category where id = ?";
        Category category = new Category();
        try {
            conn = getConnection();
            ps = conn.prepareStatement(sql);
            ps.setInt(1, id);
            rs = ps.executeQuery();
            while (rs.next()){
                category.setId(rs.getInt("id"));
                category.setName(rs.getString("name"));
                category.setDelete(rs.getBoolean("isDeleted"));
                category.setCreatedAt(rs.getTimestamp("createdAt"));
                category.setUpdatedAt(rs.getTimestamp("updatedAt"));
            }
            return category;
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Override
    public int count(String state, String keyword) {
        StringBuilder sql = new StringBuilder("select count(*) from category");
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
    public List<Category> findAll(Pageble pageble, String state, String keyword) {
        StringBuilder sql = new StringBuilder("select * from category");
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
        List<Category> categories = new ArrayList<>();
        try {
            conn = getConnection();
            ps = conn.prepareStatement(String.valueOf(sql));
            rs = ps.executeQuery();
            while (rs.next()) {
                Category category = new Category();
                category.setId(rs.getInt("id"));
                category.setName(rs.getString("name"));
                category.setDelete(rs.getBoolean("isDeleted"));
                category.setCreatedAt(rs.getTimestamp("createdAt"));
                category.setUpdatedAt(rs.getTimestamp("updatedAt"));
                categories.add(category);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return categories;

    }

    @Override
    public List<Category> findAll() {
        String sql = "select * from category where isDeleted = false";
        List<Category> categories = new ArrayList<>();
        try {
            conn = getConnection();
            ps = conn.prepareStatement(sql);
            rs = ps.executeQuery();
            while(rs.next()) {
                Category category = new Category();
                category.setId(rs.getInt("id"));
                category.setName(rs.getString("name"));
                category.setDelete(rs.getBoolean("isDeleted"));
                category.setCreatedAt(rs.getTimestamp("createdAt"));
                category.setUpdatedAt(rs.getTimestamp("updatedAt"));
                categories.add(category);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return categories;
    }


    @Override
    public void insert(Category category) {
        String sql = "INSERT INTO category(name) VALUES (?)";
        try {
            conn = super.getConnection();
            ps = conn.prepareStatement(sql);
            ps.setString(1, category.getName());
            ps.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        }
}

    @Override
    public void edit(Category category) {
        String sql = "UPDATE category SET name = ? WHERE id = ?";
        try {
            conn = super.getConnection();
            ps = conn.prepareStatement(sql);
            ps.setString(1, category.getName());
            ps.setInt(2, category.getId());
            ps.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    @Override
    public void deleteSoft(int id) {
        String sql = "UPDATE category SET isDeleted = true WHERE id = ?";
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
        String sql = "UPDATE category SET isDeleted = false WHERE id = ?";
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
        String sql = "DELETE FROM category WHERE id = ?";
        try {
            conn = super.getConnection();
            ps = conn.prepareStatement(sql);
            ps.setInt(1, id);
            ps.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
