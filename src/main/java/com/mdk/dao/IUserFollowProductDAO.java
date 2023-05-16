package com.mdk.dao;

import java.util.List;

import com.mdk.models.UserFollowProduct;

public interface IUserFollowProductDAO {
	void insert(UserFollowProduct userFollowProduct);

	void update(UserFollowProduct userFollowProduct);

	void delete(int id);

	List<UserFollowProduct> findByUserId(int id);

	UserFollowProduct findFollow(UserFollowProduct userFollowProduct);
}
