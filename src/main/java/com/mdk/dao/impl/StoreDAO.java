
package com.mdk.dao.impl;

import com.mdk.connection.DBConnection;
import com.mdk.dao.IStoreDAO;

import com.mdk.models.ImageStore;
import com.mdk.models.Store;
import com.mdk.models.User;
import com.mdk.paging.Pageble;
import com.mdk.services.IImageStoreService;
import com.mdk.services.IUserService;
import com.mdk.services.impl.ImageStoreService;
import com.mdk.services.impl.UserService;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.mdk.connection.DBConnection;
import com.mdk.dao.IStoreDAO;
import com.mdk.models.Store;
import com.mdk.services.IImageStoreService;
import com.mdk.services.IUserService;
import com.mdk.services.impl.ImageStoreService;
import com.mdk.services.impl.UserService;


public class StoreDAO extends DBConnection implements IStoreDAO {
	public Connection conn = null;
	public PreparedStatement ps = null;
	public ResultSet rs = null;
	

	@Override
	public int totalStores() {
		String sql = "SELECT COUNT(id) as total FROM store";
		int result = 0;
		try {
			conn = super.getConnection();
			ps = conn.prepareStatement(sql);
			rs = ps.executeQuery();
			while (rs.next()) {
				result = rs.getInt("total");
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
		return result;
	}

	@Override
	public List<Store> top10Store_Orders() {
		String sql = "select store.id, store.name, store.bio, store.ownerId, total from (select storeId, count(storeId) as total from orders group by storeId order by total desc limit 10) as tb join store on tb.storeId = store.id order by total DESC";
		List<Store> stores = new ArrayList<Store>();
		IUserService userService = new UserService();
		try {
			conn = super.getConnection();
			ps = conn.prepareStatement(sql);
			rs = ps.executeQuery();
			while (rs.next()) {
				Store store = new Store();
				store.setNameUser(userService.findById(rs.getInt("ownerId")).getLastname() + userService.findById(rs.getInt("ownerId")).getFirstname());
				store.setName(rs.getString("name"));
				store.setBio(rs.getString("bio"));
				store.setTotal(rs.getInt("total"));
				stores.add(store);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return stores;
	}

	@Override
	public List<Store> findAll() {
		String sql = "select * from store";
		List<Store> stores = new ArrayList<Store>();
		try {
			conn = super.getConnection();
			ps = conn.prepareStatement(sql);
			rs = ps.executeQuery();
			while (rs.next()) {
				Store store = new Store();
				store.setOpen(rs.getBoolean("isOpen"));
				store.setId(rs.getInt("id"));
				store.setName(rs.getString("name"));
				store.setBio(rs.getString("bio"));
				store.setOwnerID(rs.getInt("ownerId"));
				store.setCreatedAt(rs.getTimestamp("createdAt"));
				stores.add(store);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return stores;
	}

	@Override
	public List<Store> findAll(Pageble pageble, String keyword, String state) {
		StringBuilder sql = new StringBuilder("select * from store");
		if (state != "") {
			sql.append(" where isOpen = " + Boolean.parseBoolean(state));
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
		List<Store> stores = new ArrayList<Store>();
		try {
			conn = getConnection();
			ps = conn.prepareStatement(String.valueOf(sql));
			rs = ps.executeQuery();
			while (rs.next()) {
				Store store = new Store();
				store.setId(rs.getInt("id"));
				store.setName(rs.getString("name"));
				store.setBio(rs.getString("bio"));
				store.setOwnerID(rs.getInt("ownerId"));
				store.setRating(rs.getInt("rating"));
				store.seteWallet(rs.getDouble("eWallet"));
				stores.add(store);
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return stores;

	}

	@Override
	public void insert(Store store) {
		String sql = "insert into store(name, bio, ownerId, avatar) values(?, ?, ?, ?)";
		try {
			conn = getConnection();
			ps = conn.prepareStatement(sql);
			ps.setString(1, store.getName());
			ps.setString(2, store.getBio());
			ps.setInt(3, store.getOwnerID());
			ps.setString(4, store.getAvatar());
			ps.executeUpdate();
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}

	@Override
	public void update(Store store) {
		String sql = "update store set name = ?, bio = ?, avatar = ? where id = " + store.getId();
		try {
			conn = getConnection();
			ps = conn.prepareStatement(sql);
			ps.setString(1, store.getName());
			ps.setString(2, store.getBio());
			ps.setString(3, store.getAvatar());
			ps.executeUpdate();
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}

	@Override
	public int count(int userId) {
		String sql = "select count(*) from store where ownerId = ?";
		try {
			conn = getConnection();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, userId);
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
	public int count(String keyword, String state) {
		StringBuilder sql = new StringBuilder("select count(*) from store");
		if(state != "") {
			sql.append(" where isOpen = " + Boolean.parseBoolean(state));
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
	public Store findByUserId(int userId) {
		String sql = "select * from store where ownerId = ?";
		Store store = new Store();
		IImageStoreService imageStoreService = new ImageStoreService();
		try {
			conn = getConnection();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, userId);
			rs = ps.executeQuery();
			while (rs.next()) {
				store.setId(rs.getInt("id"));
				store.setName(rs.getString("name"));
				store.setBio(rs.getString("bio"));
				store.setOwnerID(rs.getInt("ownerId"));
				store.setOpen(rs.getBoolean("isOpen"));
				store.setAvatar(rs.getString("avatar"));
				store.setRating(rs.getInt("rating"));
				store.seteWallet(rs.getDouble("eWallet"));
				store.setImages(imageStoreService.findByStoreId(rs.getInt("id")));
				return store;
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public int totalCustomer(int storeId) {
		String sql = "select userId, count(*) from orders where storeId = ? group by userId";
		try {

			conn = super.getConnection();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, storeId);
			rs = ps.executeQuery();
			List<Integer> user = new ArrayList<>();
			while (rs.next()) {
				user.add(rs.getInt("userId"));
			}
			return user.size();
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return 0;
	}

	@Override
	public int totalProduct(int storeId) {
		String sql = "select sum(quantity) from product where storeId = ?";
		try {
			conn = getConnection();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, storeId);
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
	public int totalOrders(int storeId) {
		String sql = "select count(*) from orders where storeId = ? group by storeId";
		try {
			conn = getConnection();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, storeId);
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
	public int totalSale(int storeId) {
		String sql = "select sum(sold) from product where storeId = ?";
		try {
			conn = getConnection();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, storeId);
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
	public double revenueOfMonth(int storeId, String month, String year) {
		String sql = "select sum(amountToStore) from orders where status like 'delivered' and storeId = ? and month" +
				"(createdAt) = ? and year(createdAt) = ?";
		try {
			conn = getConnection();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, storeId);
			ps.setString(2, month);
			ps.setString(3, year);
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
	public double transactionOfMonth(int storeId, boolean isUp, String month, String year) {
		String sql = "select sum(amount) from transaction where storeId = ? and isUp = ? and month(createdAt) = ? and year(createdAt) = ?";
		try {
			conn = getConnection();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, storeId);
			ps.setBoolean(2, isUp);
			ps.setString(3, month);
			ps.setString(4, year);
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
	public Store findById(int id) {
		String sql = "select * from store where id = ?";
		Store store = new Store();
		IImageStoreService imageStoreService = new ImageStoreService();
		IUserService userService = new UserService();
		try {
			conn = getConnection();
			ps = conn.prepareStatement(sql);
			ps.setInt(1, id);
			rs = ps.executeQuery();
			while (rs.next()) {
				store.setId(rs.getInt("id"));
				store.setName(rs.getString("name"));
				store.setBio(rs.getString("bio"));
				store.setOwnerID(rs.getInt("ownerId"));
				store.setOpen(rs.getBoolean("isOpen"));
				store.setAvatar(rs.getString("avatar"));
				store.setRating(rs.getInt("rating"));
				store.seteWallet(rs.getDouble("eWallet"));
				store.setOwner(userService.findById(store.getOwnerID()));
				store.setImages(imageStoreService.findByStoreId(rs.getInt("id")));
				return store;
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return null;
	}

	@Override
	public List<Store> findAllByName(String keyword) {
		String sql = "select * from store where name like CONCAT('%', ?, '%')";
		List<Store> stores = new ArrayList<Store>();
		IImageStoreService imageStoreService = new ImageStoreService();
		IUserService userService = new UserService();
		try {
			conn = super.getConnection();
			ps = conn.prepareStatement(sql);
			ps.setString(1, keyword);
			rs = ps.executeQuery();
			while (rs.next()) {
				Store store = new Store();
				store.setId(rs.getInt("id"));
				store.setName(rs.getString("name"));
				store.setBio(rs.getString("bio"));

				store.setOwnerID(rs.getInt("ownerId"));
				store.setRating(rs.getInt("rating"));
				store.setOwner(userService.findById(store.getOwnerID()));
				store.setImages(imageStoreService.findByStoreId(rs.getInt("id")));
				// store.setTotal(rs.getInt("total"));

				stores.add(store);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return stores;
	}

	@Override
	public List<String> findOwnerEmailByStoreId(int id) {
		StringBuilder sql = new StringBuilder("select user.email, user.firstname, user.lastname from store inner join user on store.ownerId = user.id where store.id = ?");
		List<String> datas = new ArrayList<String>();
		try {
			conn = getConnection();
			ps = conn.prepareStatement(String.valueOf(sql));
			ps.setInt(1, id);
			rs = ps.executeQuery();
			while (rs.next()) {
				datas.add(rs.getString("email"));
				datas.add(rs.getString("firstname"));
				datas.add(rs.getString("lastname"));
			}
		} catch (SQLException e) {
			e.printStackTrace();
		}
		return datas;
	}

	@Override
	public void updateWallet(int id, double eWallet) {
		String sql = "UPDATE store "
				+ "SET eWallet = ? "
				+ "WHERE id = ?";
		try {
			conn = super.getConnection();
			ps = conn.prepareStatement(sql);
			ps.setDouble(1, eWallet);
			ps.setInt(2, id);
			ps.executeUpdate();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Override
	public void updateRating(int storeId, int rating) {
		StringBuilder sql = new StringBuilder("update store set rating = ? where id = ?");
		try {
			conn = getConnection();
			ps = conn.prepareStatement(String.valueOf(sql));
			ps.setInt(1, rating);
			ps.setInt(2, storeId);

			ps.executeUpdate();
		} catch (SQLException e) {
			e.printStackTrace();
		}
	}
	public void deleteSoft(int id) {
		String sql = "UPDATE store SET isOpen = false WHERE id = ?";
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
		String sql = "DELETE FROM store WHERE id = ?";
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
		String sql = "UPDATE store SET isOpen = true WHERE id = ?";
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
	public List<Store> findAllForReport() {
		String sql = "SELECT * FROM store";
		List<Store> stores = new ArrayList<Store>();
		try {
			conn = super.getConnection();
			ps = conn.prepareStatement(sql);
			rs = ps.executeQuery();
			while (rs.next()) {
				Store store = new Store();
				store.setId(rs.getInt("id"));
				store.setName(rs.getString("name"));
				store.setBio(rs.getString("bio"));
				store.setOwnerID(rs.getInt("ownerID"));
				store.setAvatar(rs.getString("avatar"));  //tạm để lấy tên chủ cửa hàng đưa vào đây
				store.setOpen(rs.getBoolean("isOpen"));
				store.setRating(rs.getInt("rating"));
				store.seteWallet(rs.getDouble("eWallet"));
				stores.add(store);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return stores;
	}
}
