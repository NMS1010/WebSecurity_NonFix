package com.mdk.services.impl;

import java.util.List;

import com.mdk.dao.IUserFollowProductDAO;
import com.mdk.dao.impl.UserFollowProductDAO;
import com.mdk.models.UserFollowProduct;
import com.mdk.services.IUserFollowProductService;

public class UserFollowProductService implements IUserFollowProductService {
	IUserFollowProductDAO userFollowProductDAO = new UserFollowProductDAO();
	
	@Override
	public void insert(UserFollowProduct userFollowProduct) {
		userFollowProductDAO.insert(userFollowProduct);
		
	}

	@Override
	public void delete(int id) {
		userFollowProductDAO.delete(id);
	}

	@Override
	public List<UserFollowProduct> findByUserId(int id) {
		return userFollowProductDAO.findByUserId(id);
	}

	@Override
	public UserFollowProduct findFollow(UserFollowProduct userFollowProduct) {
		return userFollowProductDAO.findFollow(userFollowProduct);
	}

	@Override
	public void update(UserFollowProduct userFollowProduct) {
		userFollowProductDAO.update(userFollowProduct);
	}

}
