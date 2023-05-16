package com.mdk.services.impl;

import java.util.List;

import com.mdk.dao.IUserFollowStoreDAO;
import com.mdk.dao.impl.UserFollowStoreDAO;
import com.mdk.models.UserFollowStore;
import com.mdk.paging.Pageble;
import com.mdk.services.IUserFollowStoreService;

public class UserFollowStoreService implements IUserFollowStoreService {
	IUserFollowStoreDAO userFollowStoreDAO = new UserFollowStoreDAO();
	
	@Override
	public void insert(UserFollowStore userFollowStore) {
		userFollowStoreDAO.insert(userFollowStore);
	}

	@Override
	public void delete(int id) {
		userFollowStoreDAO.delete(id);
	}

	@Override
	public List<UserFollowStore> findByUserId(int id) {
		return userFollowStoreDAO.findByUserId(id);
	}

	@Override
	public UserFollowStore findFollow(UserFollowStore userFollowStore) {
		return userFollowStoreDAO.findFollow(userFollowStore);
	}

	@Override
	public void update(UserFollowStore userFollowStore) {
		userFollowStoreDAO.update(userFollowStore);
	}

    @Override
    public List<UserFollowStore> findByStoreId(Pageble pageble, int storeId) {
        return userFollowStoreDAO.findByStoreId(pageble, storeId);
    }

    

}
