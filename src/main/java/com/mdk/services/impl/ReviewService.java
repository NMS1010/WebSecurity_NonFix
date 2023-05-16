package com.mdk.services.impl;

import java.util.List;

import com.mdk.dao.IReviewDAO;
import com.mdk.dao.impl.ReviewDAO;
import com.mdk.models.Review;
import com.mdk.paging.Pageble;
import com.mdk.services.IReviewService;

public class ReviewService implements IReviewService {
	IReviewDAO reviewDAO = new ReviewDAO();
	
	@Override
	public void insert(Review review) {
		reviewDAO.insert(review);
	}

	@Override
	public void update(Review review) {
		reviewDAO.update(review);
	}

	@Override
	public void delete(int id) {
		reviewDAO.delete(id);
	}

	@Override
	public List<Review> findByProduct(int productId) {
		return reviewDAO.findByProduct(productId);
	}

	@Override
	public List<Review> findByStore(int storeId) {
		return reviewDAO.findByStore(storeId);
	}

	@Override
	public Review findReview(Review review) {
		return reviewDAO.findReview(review);
	}

    @Override
    public List<Review> findByStore(Pageble pageble, int storeId, String star, String searchKey) {
        return reviewDAO.findByStore(pageble, storeId, star, searchKey);
    }

    @Override
    public int count(int storeId, String star, String searchKey) {
        return reviewDAO.count(storeId, star, searchKey);
    }

}
