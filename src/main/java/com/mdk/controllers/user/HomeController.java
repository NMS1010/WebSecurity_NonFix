package com.mdk.controllers.user;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.mdk.models.Cart;
import com.mdk.models.Product;
import com.mdk.models.User;
import com.mdk.services.ICartService;
import com.mdk.services.IProductService;
import com.mdk.services.IUserService;
import com.mdk.services.impl.CartService;
import com.mdk.services.impl.ProductService;
import com.mdk.services.impl.UserService;
import com.mdk.utils.SessionUtil;

import static com.mdk.utils.AppConstant.*;

@WebServlet(urlPatterns = { "/home", "/web" })
public class HomeController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	IProductService productService = new ProductService();
	IUserService userService = new UserService();
	ICartService cartService = new CartService();

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String url = req.getRequestURL().toString();

		if (url.contains("/home") || url.contains("/web")) {
			List<Product> productList = productService.findAllProductPermitted();
			List<Product> topSellerList = productService.getTopSeller(10);
			List<Product> topRatingList = productService.getTopRating(10);

			if ((User) SessionUtil.getInstance().getValue(req, USER_MODEL) != null) {
				User user = (User) SessionUtil.getInstance().getValue(req, USER_MODEL);

				List<Cart> carts = cartService.findByUserId(user.getId());
				int countOfCarts = carts.stream()
						.mapToInt(o1 -> o1.getCartItems().stream().mapToInt(o2 -> o2.getCount()).sum()).sum();

				SessionUtil.getInstance().putValue(req, CART_HEADER, carts);
				SessionUtil.getInstance().putValue(req, COUNT_CART_HEADER, countOfCarts);
			}
			
			req.setAttribute("productList", productList);
			req.setAttribute("topSellerList", topSellerList);
			req.setAttribute("topRatingList", topRatingList);

			req.getRequestDispatcher("/views/web/home.jsp").forward(req, resp);
		}
	}

	protected void baseInfo(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

		User user = (User) SessionUtil.getInstance().getValue(req, USER_MODEL);
		req.setAttribute("user", user);
		List<Cart> carts = cartService.findByUserId(user.getId());
		int countOfCarts = carts.stream().mapToInt(o1 -> o1.getCartItems().stream().mapToInt(o2 -> o2.getCount()).sum())
				.sum();
		req.setAttribute("carts", carts);
		req.setAttribute("countOfCarts", countOfCarts);
	}
}
