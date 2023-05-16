package com.mdk.controllers.user;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.mdk.models.Product;
import com.mdk.models.Review;
import com.mdk.models.Store;
import com.mdk.models.User;
import com.mdk.services.IProductService;
import com.mdk.services.IReviewService;
import com.mdk.services.IStoreService;
import com.mdk.services.IUserService;
import com.mdk.services.impl.ProductService;
import com.mdk.services.impl.ReviewService;
import com.mdk.services.impl.StoreService;
import com.mdk.services.impl.UserService;

@WebServlet(urlPatterns = { "/web/store/search", "/web/store/detail", "/home/store/search", "/home/store/detail" })
public class StoreController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	IStoreService storeService = new StoreService();
	IUserService userService = new UserService();
	IProductService productService = new ProductService();
	IReviewService reviewService = new ReviewService();

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String url = req.getRequestURL().toString();

		if (url.contains("search")) {
			String searchkeyword = "";
			List<Store> storeSearchList = storeService.findAllByName(searchkeyword);
			List<User> ownerSearchList = userService.findAll();
			req.setAttribute("storeSearchList", storeSearchList);
			req.setAttribute("ownerSearchList", ownerSearchList);
			req.getRequestDispatcher("/views/web/searchstore.jsp").forward(req, resp);
		} else if (url.contains("detail")) {
			int id = Integer.parseInt(req.getParameter("id"));
			Store store = storeService.findById(id);
			User owner = userService.findById(store.getId());
			List<Product> storeProductList = productService.findByStoreId(store.getId());
			List<Review> reviewList = reviewService.findByStore(store.getId());

			req.setAttribute("store", store);
			req.setAttribute("owner", owner);
			req.setAttribute("storeProductList", storeProductList);
			req.setAttribute("reviewList", reviewList);
			req.getRequestDispatcher("/views/web/storedetail.jsp").forward(req, resp);
		}

	}

	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String url = req.getRequestURL().toString();

		if (url.contains("search")) {
			req.setCharacterEncoding("UTF-8");
			resp.setCharacterEncoding("UTF-8");
			String searchkeyword = req.getParameter("searchkeyword");
			List<Store> storeSearchList = storeService.findAllByName(searchkeyword);
			List<User> ownerSearchList = userService.findAll();
			req.setAttribute("storeSearchList", storeSearchList);
			req.setAttribute("ownerSearchList", ownerSearchList);
			req.getRequestDispatcher("/views/web/searchstore.jsp").forward(req, resp);
		}
	}
}
