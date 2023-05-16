package com.mdk.controllers.user;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.mdk.models.User;
import com.mdk.models.UserFollowProduct;
import com.mdk.models.UserFollowStore;
import com.mdk.services.IUserFollowProductService;
import com.mdk.services.IUserFollowStoreService;
import com.mdk.services.impl.UserFollowProductService;
import com.mdk.services.impl.UserFollowStoreService;
import com.mdk.utils.SessionUtil;

@WebServlet(urlPatterns = { "/web/following", "/web/following/book/add", "/web/following/book/delete",
		"/web/following/store/add", "/web/following/store/delete" })
public class UserFollowingController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	IUserFollowProductService userFollowProductService = new UserFollowProductService();
	IUserFollowStoreService userFollowStoreService = new UserFollowStoreService();

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String url = req.getRequestURL().toString();

		if (url.contains("/web/following/store/add")) {
			User user = (User) SessionUtil.getInstance().getValue(req, "USERMODEL");
			UserFollowStore userFollowStore = new UserFollowStore();
			userFollowStore.setUserId(user.getId());
			userFollowStore.setStoreId(Integer.parseInt(req.getParameter("id")));
			if (userFollowStoreService.findFollow(userFollowStore) == null) {
				userFollowStoreService.insert(userFollowStore);
			} else {
				userFollowStore.setId(userFollowStoreService.findFollow(userFollowStore).getId());
				userFollowStoreService.update(userFollowStore);
			}
			resp.sendRedirect(req.getHeader("referer"));
		} else if (url.contains("/web/following/store/delete")) {
			userFollowStoreService.delete(Integer.parseInt(req.getParameter("id")));
			resp.sendRedirect(req.getHeader("referer"));
		} else if (url.contains("/web/following/book/add")) {
			User user = (User) SessionUtil.getInstance().getValue(req, "USERMODEL");
			UserFollowProduct userFollowProduct = new UserFollowProduct();
			userFollowProduct.setUserId(user.getId());
			userFollowProduct.setProductId(Integer.parseInt(req.getParameter("id")));

			if (userFollowProductService.findFollow(userFollowProduct) == null) {
				userFollowProductService.insert(userFollowProduct);
			} else {
				userFollowProduct.setId(userFollowProductService.findFollow(userFollowProduct).getId());
				userFollowProductService.update(userFollowProduct);
			}
			resp.sendRedirect(req.getHeader("referer"));
		} else if (url.contains("/web/following/book/delete")) {
			userFollowProductService.delete(Integer.parseInt(req.getParameter("id")));
			resp.sendRedirect(req.getHeader("referer"));
		} else if (url.contains("/web/following")) {
			User user = (User) SessionUtil.getInstance().getValue(req, "USERMODEL");
			List<UserFollowProduct> userFollowProductList = userFollowProductService.findByUserId(user.getId());
			List<UserFollowStore> userFollowStoreList = userFollowStoreService.findByUserId(user.getId());

			req.setAttribute("userFollowProductList", userFollowProductList);
			req.setAttribute("userFollowStoreList", userFollowStoreList);
			req.getRequestDispatcher("/views/web/following.jsp").forward(req, resp);
		}

	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String url = req.getRequestURL().toString();
		System.out.print("post");
	}
}
