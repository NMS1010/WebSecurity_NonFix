package com.mdk.controllers.user;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.mdk.models.Category;
import com.mdk.models.Product;
import com.mdk.models.Review;
import com.mdk.models.Store;
import com.mdk.services.ICategoryService;
import com.mdk.services.IProductService;
import com.mdk.services.IReviewService;
import com.mdk.services.IStoreService;
import com.mdk.services.impl.CategoryService;
import com.mdk.services.impl.ProductService;
import com.mdk.services.impl.ReviewService;
import com.mdk.services.impl.StoreService;

@WebServlet(urlPatterns = { "/web/book/search", "/web/book/detail", "/home/book/search", "/home/book/detail" })
public class ProductController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	IProductService productService = new ProductService();
	ICategoryService categoryService = new CategoryService();
	IStoreService storeService = new StoreService();
	IReviewService reviewService = new ReviewService();
	
	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String url = req.getRequestURL().toString();
		if (url.contains("search")) {
			List<Category> categoryList = categoryService.findAll();
			List<Store> storeList = storeService.findAll();
			List<Product> searchProductList = productService.findBySearching("", 0, 0, -1, 0.0, 1000000.0);

			req.setAttribute("categoryList", categoryList);
			req.setAttribute("storeList", storeList);
			req.setAttribute("searchProductList", searchProductList);
			req.getRequestDispatcher("/views/web/searchbook.jsp").forward(req, resp);
		} else if (url.contains("detail")) {
			int id = Integer.parseInt(req.getParameter("id"));
			Product product = productService.findOneById(id);
			List<Review> reviewList = reviewService.findByProduct(id);
			req.setAttribute("product", product);
			req.setAttribute("reviewList", reviewList);
			req.getRequestDispatcher("/views/web/productdetail.jsp").forward(req, resp);

		}

	}

	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String url = req.getRequestURL().toString();
		if (url.contains("search")) {
			req.setCharacterEncoding("UTF-8");
			resp.setCharacterEncoding("UTF-8");
			List<Category> categoryList = categoryService.findAll();
			List<Store> storeList = storeService.findAll();
			String searchkeyword = req.getParameter("search");

			int categorySearch = Integer.parseInt(req.getParameter("category"));
			int storeSearch = Integer.parseInt(req.getParameter("store"));
			int rating = Integer.parseInt(req.getParameter("rating"));
			double minPrice = Double.parseDouble(req.getParameter("minPrice"));
			double maxPrice = Double.parseDouble(req.getParameter("maxPrice"));

			List<Product> searchProductList = productService.findBySearching(searchkeyword.trim(), categorySearch,
					storeSearch, rating, minPrice, maxPrice);

			req.setAttribute("categoryList", categoryList);
			req.setAttribute("storeList", storeList);

			req.setAttribute("searchProductList", searchProductList);

			req.setAttribute("searchkeyword", searchkeyword);
			req.setAttribute("categorySearch", categorySearch);
			req.setAttribute("storeSearch", storeSearch);
			req.setAttribute("rating", rating);
			req.setAttribute("minPrice", minPrice);
			req.setAttribute("maxPrice", maxPrice);

			req.getRequestDispatcher("/views/web/searchbook.jsp").forward(req, resp);
		}
	}
}