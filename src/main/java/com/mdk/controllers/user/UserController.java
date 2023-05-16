package com.mdk.controllers.user;

import static com.mdk.utils.AppConstant.USER_MODEL;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;

import com.mdk.models.ImageStore;
import com.mdk.models.User;
import com.mdk.services.IUserService;
import com.mdk.services.impl.UserService;
import com.mdk.utils.AppConstant;
import com.mdk.utils.DeleteImageUtil;
import com.mdk.utils.SessionUtil;
import com.mdk.utils.UploadUtil;

@MultipartConfig(fileSizeThreshold = 1024 * 1024 * 10, // 10MB
		maxFileSize = 1024 * 1024 * 50, // 50MB
		maxRequestSize = 1024 * 1024 * 50) // 50MB

@WebServlet(urlPatterns = { "/web/user/search", "/web/user/profile", "/web/user/edit", "/web/user/edit/update",
		"/web/user/edit/eWallet/add", "/web/user/edit/updatepassword" })
public class UserController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	IUserService userService = new UserService();

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String url = req.getRequestURL().toString();
		req.setCharacterEncoding("UTF-8");
		resp.setCharacterEncoding("UTF-8");

		if (url.contains("search")) {

			req.getRequestDispatcher("/views/web/searchuser.jsp").forward(req, resp);
		} else if (url.contains("profile")) {
			int id = ((User) SessionUtil.getInstance().getValue(req, USER_MODEL)).getId();
			User user = userService.findById(id);

			req.setAttribute("user", user);
			req.getRequestDispatcher("/views/web/userprofile.jsp").forward(req, resp);
		} else if (url.contains("/web/user/edit")) {
			int id = ((User) SessionUtil.getInstance().getValue(req, USER_MODEL)).getId();
			User user = userService.findById(id);

			req.setAttribute("id_card_exist", req.getParameter("id_card_exist"));
			req.setAttribute("phone_exist", req.getParameter("phone_exist"));
			req.setAttribute("id", id);
			req.setAttribute("user", user);
			req.getRequestDispatcher("/views/web/editprofile.jsp").forward(req, resp);
		}
	}

	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String url = req.getRequestURL().toString();
		req.setCharacterEncoding("UTF-8");
		resp.setCharacterEncoding("UTF-8");
		if (url.contains("search")) {

			String searchkeyword = req.getParameter("searchkeyword");
			List<User> userListSearch = userService.findBySearching(searchkeyword);

			req.setAttribute("userListSearch", userListSearch);
			req.getRequestDispatcher("/views/web/searchuser.jsp").forward(req, resp);
		} else if (url.contains("/web/user/edit/eWallet/add")) {
			int id = ((User) SessionUtil.getInstance().getValue(req, USER_MODEL)).getId();
			User user = userService.findById(id);
			userService.updateWallet(id, user.geteWallet() + Double.parseDouble(req.getParameter("eWallet")));
			user = userService.findById(id);
			SessionUtil.getInstance().putValue(req, USER_MODEL, user);
			resp.sendRedirect(req.getContextPath() + "/web/user/edit");

		} else if (url.contains("updatepassword")) {
			int id = ((User) SessionUtil.getInstance().getValue(req, USER_MODEL)).getId();
			String pass = req.getParameter("new_pass");
			userService.updatePass(id, pass);
			User user = userService.findById(id);
			SessionUtil.getInstance().putValue(req, USER_MODEL, user);
			resp.sendRedirect(req.getContextPath() + "/web/user/edit");

		} else if (url.contains("update")) {
			int id = ((User) SessionUtil.getInstance().getValue(req, USER_MODEL)).getId();
			User user = userService.findById(id);
			String phone = user.getPhone();
			String id_card = user.getId_card();
			System.out.print((phone != req.getParameter("phone")));
			if ((userService.checkPhoneExist(req.getParameter("phone")) > 0)
					&& (!phone.equals(req.getParameter("phone")))) {
				resp.sendRedirect(req.getContextPath() + "/web/user/edit?phone_exist=true");
				return;
			}

			if ((userService.checkId_card(req.getParameter("id_card")) > 0)
					&& (!id_card.equals(req.getParameter("id_card")))) {
				resp.sendRedirect(req.getContextPath() + "/web/user/edit?id_card_exist=true");
				return;
			}
			update(req, resp);
			resp.sendRedirect(req.getContextPath() + "/web/user/edit");
		}
	}

	protected void update(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

		int id = ((User) SessionUtil.getInstance().getValue(req, USER_MODEL)).getId();
		User user = new User();
		user.setId(id);
		user.setFirstname(req.getParameter("firstname"));
		user.setLastname(req.getParameter("lastname"));
		user.setEmail(req.getParameter("email"));
		user.setPhone(req.getParameter("phone"));
		user.setId_card(req.getParameter("id_card"));
		user.setSex(req.getParameter("sex"));

		String image = new String();
		String oldimage = userService.findById(id).getAvatar();

		Collection<Part> parts = req.getParts();
		for (Part filePart : parts) {
			if (filePart.getHeader("content-disposition").contains("filename=")) {
				String fileName = "" + System.currentTimeMillis();
				String realPath = AppConstant.UPLOAD_USER_DIRECTORY;
				if (filePart.getName().equals("avatar")) {
					if (filePart.getSize() == 0) {
						user.setAvatar(oldimage);
					} else {
						if (oldimage != null) {
							String fileNameAvatar = oldimage;
							String userFolder = AppConstant.UPLOAD_USER_DIRECTORY;
							DeleteImageUtil.processDelete(userFolder, fileNameAvatar);
						}
						image = UploadUtil.processUpload(filePart.getName(), req, realPath, fileName);
					}
				} else {
					if (filePart.getSize() == 0) {
						image = oldimage;
					} else {
						if (oldimage != null) {
							// xoa anh cu
							String fileNameImg = oldimage;
							File file = new File(AppConstant.UPLOAD_USER_DIRECTORY + "\\" + fileNameImg);
							if (file.delete()) {
								System.out.println("Đã xóa");
							} else {
								System.out.println(AppConstant.UPLOAD_USER_DIRECTORY + "\\" + fileNameImg);
							}
						}
						image = UploadUtil.processUpload(filePart.getName(), req, realPath, fileName);
					}
				}
			}
		}

		user.setAvatar(image);
		userService.update(user);

		User newuser = userService.findById(id);
		SessionUtil.getInstance().putValue(req, USER_MODEL, newuser);
		req.setAttribute("user", newuser);
	}

	protected void updatePassword(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		req.setCharacterEncoding("UTF-8");
		resp.setCharacterEncoding("UTF-8");

		User user = new User();
		List<ImageStore> images = new ArrayList<>();

		user.setPassword(req.getParameter("password"));
		userService.update(user);
	}
}
