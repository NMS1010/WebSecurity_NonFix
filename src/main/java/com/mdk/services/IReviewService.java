package com.mdk.services;

import java.util.List;

import com.mdk.models.Review;
import com.mdk.paging.Pageble;

public interface IReviewService {
	void insert(Review review);
	void update(Review review);
	void delete(int id);
	List<Review> findByProduct(int productId);
	List<Review> findByStore(int storeId);
	Review findReview(Review review);
    List<Review> findByStore(Pageble pageble, int storeId, String star, String searchKey);
    int count(int storeId, String star, String searchKey);
}
