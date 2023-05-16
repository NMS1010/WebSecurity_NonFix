package com.mdk.services;

import java.util.List;

import com.mdk.models.UserFollowProduct;

public interface IUserFollowProductService {
	void insert(UserFollowProduct userFollowProduct);
	
	void update(UserFollowProduct userFollowProduct);

	void delete(int id);

	List<UserFollowProduct> findByUserId(int id);

	UserFollowProduct findFollow(UserFollowProduct userFollowProduct);
	
}
