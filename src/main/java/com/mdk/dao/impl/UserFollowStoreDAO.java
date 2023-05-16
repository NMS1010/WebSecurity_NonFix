package com.mdk.dao.impl;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.mdk.connection.DBConnection;
import com.mdk.dao.IUserFollowStoreDAO;
import com.mdk.models.UserFollowProduct;
import com.mdk.models.UserFollowStore;
import com.mdk.paging.Pageble;
import com.mdk.services.IProductService;
import com.mdk.services.IStoreService;
import com.mdk.services.IUserService;
import com.mdk.services.impl.ProductService;
import com.mdk.services.impl.StoreService;
import com.mdk.services.impl.UserService;

public class UserFollowStoreDAO extends DBConnection implements IUserFollowStoreDAO {

	public Connection conn = null;
	public PreparedStatement ps = null;
	public ResultSet rs = null;

	@Override
	public void insert(UserFollowStore userFollowStore) {
		String sql = "insert into userfollowstore(userId, storeId) values(?, ?)";
		try {
			conn = getConnection();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, userFollowStore.getUserId());
			ps.setInt(2, userFollowStore.getStoreId());
			ps.executeUpdate();
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void delete(int id) {
		String sql = "delete from userfollowstore where id = ?";
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
	public List<UserFollowStore> findByUserId(int id) {
		String sql = "select * from userfollowstore where userId = ?";
		List<UserFollowStore> userFollowStores = new ArrayList<UserFollowStore>();
		IUserService userService = new UserService();
		IStoreService storeService = new StoreService();
		try {
			conn = getConnection();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, id);
			rs = ps.executeQuery();
			while (rs.next()) {
				UserFollowStore userFollowStore = new UserFollowStore();
				userFollowStore.setId(rs.getInt("id"));
				userFollowStore.setUserId(rs.getInt("userId"));
				userFollowStore.setStoreId(rs.getInt("storeId"));
				userFollowStore.setStore(storeService.findById(userFollowStore.getStoreId()));
				userFollowStore.setUser(userService.findById(userFollowStore.getUserId()));
				userFollowStores.add(userFollowStore);
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return userFollowStores;
	}

	@Override
	public UserFollowStore findFollow(UserFollowStore userFollowStore) {
		String sql = "select * from userfollowstore where userId = ? AND storeId = ?";
		IUserService userService = new UserService();
		IStoreService storeService = new StoreService();
		try {
			conn = getConnection();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, userFollowStore.getUserId());
			ps.setInt(2, userFollowStore.getStoreId());
			
			rs = ps.executeQuery();
			while (rs.next()) {
				UserFollowStore new_userFollowStore = new UserFollowStore();
				new_userFollowStore.setId(rs.getInt("id"));
				new_userFollowStore.setUserId(rs.getInt("userId"));
				new_userFollowStore.setStoreId(rs.getInt("storeId"));
				new_userFollowStore.setStore(storeService.findById(userFollowStore.getStoreId()));
				new_userFollowStore.setUser(userService.findById(userFollowStore.getUserId()));
				return new_userFollowStore;
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public void update(UserFollowStore userFollowStore) {
		String sql = "update userfollowstore "
				+ "set userId = ?, storeId = ? "
				+ "where id = ? ";
		try {
			conn = getConnection();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, userFollowStore.getUserId());
			ps.setInt(2, userFollowStore.getStoreId());
			ps.setInt(3, userFollowStore.getId());
			ps.executeUpdate();
		} catch (SQLException e) {
			e.printStackTrace();
		}	}

    @Override
    public List<UserFollowStore> findByStoreId(Pageble pageble, int storeId) {
        StringBuilder sql = new StringBuilder("select * from userfollowstore where storeId = ?");
        if (pageble.getSorter() != null) {
            sql.append(" order by " + pageble.getSorter().getSortName() + " " + pageble.getSorter().getSortBy() + "");
        }
        if (pageble.getOffset() != null && pageble.getLimit() != null) {
            sql.append(" limit " + pageble.getOffset() + ", " + pageble.getLimit() + "");
        }
        List<UserFollowStore> userFollowStores = new ArrayList<UserFollowStore>();
        IUserService userService = new UserService();
        IStoreService storeService = new StoreService();
        try {
            conn = getConnection();
            ps = conn.prepareStatement(String.valueOf(sql));
            ps.setInt(1, storeId);
            rs = ps.executeQuery();
            while (rs.next()) {
                UserFollowStore userFollowStore = new UserFollowStore();
                userFollowStore.setId(rs.getInt("id"));
                userFollowStore.setUserId(rs.getInt("userId"));
                userFollowStore.setStoreId(rs.getInt("storeId"));
                userFollowStore.setStore(storeService.findById(userFollowStore.getStoreId()));
                userFollowStore.setUser(userService.findById(userFollowStore.getUserId()));
                userFollowStores.add(userFollowStore);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return userFollowStores;
    }

}
