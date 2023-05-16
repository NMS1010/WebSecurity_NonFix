package com.mdk.services;

import java.util.List;

import com.mdk.models.UserFollowStore;
import com.mdk.paging.Pageble;

public interface IUserFollowStoreService {
	void insert(UserFollowStore userFollowStore);

	void update(UserFollowStore userFollowStore);

	void delete(int id);

	List<UserFollowStore> findByUserId(int id);
	List<UserFollowStore> findByStoreId(Pageble pageble, int storeId);

	UserFollowStore findFollow(UserFollowStore userFollowStore);
}
