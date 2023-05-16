package com.mdk.controllers.user;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.mdk.models.Orders;
import com.mdk.models.Product;
import com.mdk.models.Review;
import com.mdk.models.Store;
import com.mdk.models.User;
import com.mdk.services.IOrdersService;
import com.mdk.services.IProductService;
import com.mdk.services.IReviewService;
import com.mdk.services.IStoreService;
import com.mdk.services.impl.OrdersService;
import com.mdk.services.impl.ProductService;
import com.mdk.services.impl.ReviewService;
import com.mdk.services.impl.StoreService;
import com.mdk.utils.SessionUtil;

@WebServlet(urlPatterns = { "/web/book/review", "/web/book/review/add" })
public class ReviewController extends HttpServlet {
	IProductService productService = new ProductService();
	IReviewService reviewService = new ReviewService();
	IOrdersService ordersService = new OrdersService();
	IStoreService storeService = new StoreService();

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String url = req.getRequestURL().toString();
		if (url.contains("review")) {
			int productId = Integer.parseInt(req.getParameter("product"));
			int ordersId = Integer.parseInt(req.getParameter("orders"));
			User user = (User) SessionUtil.getInstance().getValue(req, "USERMODEL");
			Product product = productService.findOneById(productId);
			Orders orders = ordersService.findById(ordersId);
			req.setAttribute("user", user);
			req.setAttribute("product", product);
			req.setAttribute("orders", orders);
			req.getRequestDispatcher("/views/web/reviewproduct.jsp").forward(req, resp);
		}

	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String url = req.getRequestURL().toString();
		req.setCharacterEncoding("UTF-8");
		resp.setCharacterEncoding("UTF-8");

		if (url.contains("add")) {
			int productid = Integer.parseInt(req.getParameter("product"));
			int ordersid = Integer.parseInt(req.getParameter("orders"));
			int storeid = productService.findOneById(productid).getStoreId();
			int rating = Integer.parseInt(req.getParameter("rating_value"));
			String content = (req.getParameter("content"));
			User user = (User) SessionUtil.getInstance().getValue(req, "USERMODEL");
			Review review = new Review();
			review.setUserId(user.getId());
			review.setProductId(productid);
			review.setOrdersId(ordersid);
			review.setStoreId(storeid);
			
			review.setStars(rating);
			review.setContent(content);
			if(reviewService.findReview(review)==null)
			{
				reviewService.insert(review);
			}
			else
			{
				review.setId(reviewService.findReview(review).getId());
				reviewService.update(review);
			}
			changeRating(req,resp);
			resp.sendRedirect(req.getContextPath() + "/web/book/review?orders="+ordersid+"&product="+productid);
		}
	}
	
	protected void changeRating(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		List<Review> reviewProduct = reviewService.findByProduct(Integer.parseInt(req.getParameter("product")));
		Double ratingProduct = 0.0;
		for(Review review: reviewProduct) {
			ratingProduct+=review.getStars();
		}
		Product product = productService.findOneById(Integer.parseInt(req.getParameter("product")));
	    productService.updateRating(product.getId(),(int)Math.round(ratingProduct/=reviewProduct.size()));
	    
	    List<Review> reviewStore = reviewService.findByStore(product.getStoreId());
	    Double ratingStore = 0.0;
		for(Review review: reviewStore) {
			ratingStore+=review.getStars();
		}
		Store store = storeService.findById(product.getStoreId());
		storeService.updateRating(store.getId(), (int)Math.round(ratingStore/=reviewStore.size()));
	}
}
