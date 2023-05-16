package com.mdk.controllers.admin;
import com.mdk.models.User;
import com.mdk.paging.PageRequest;
import com.mdk.paging.Pageble;
import com.mdk.services.IUserService;
import com.mdk.services.impl.UserService;
import com.mdk.utils.ExportExcel;

import java.io.IOException;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static com.mdk.utils.AppConstant.TOTAL_ITEM_IN_PAGE;

@WebServlet(urlPatterns = {"/admin/user/all", "/admin/user/closest"})
public class UserAdminController extends HttpServlet{
	private static final long serialVersionUID = 1L;
	 IUserService userService = new UserService();

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String url = req.getRequestURL().toString();
		if (url.contains("user/all")) {
			usersPage(req, resp);
			List<User> reportUser = userService.findAllForReport();
			final String excelFilePath = "E:\\reportUser.xls";
			ExportExcel.writeExcel(reportUser, excelFilePath, User.getColumns(), "reportUser");
			req.getRequestDispatcher("/views/admin/user/all.jsp").forward(req, resp);
		}
		else if (url.contains("user/closest")) {
			LocalDate localDate = LocalDate.now();
			List<User> userList = userService.top10Users_Orders();
			List<User> userListAll = userService.findAll();
			List<Integer> arrEachMonth = new ArrayList<Integer>();
			List<Integer> arrEachMonthInLastYear = new ArrayList<Integer>();

			List<Integer> arr = new ArrayList<Integer>();
			int total = userListAll.size();
			int male = 0, female = 0;
			for (User item: userListAll)
				if (item.getSex().equals("Nam"))
					male++;
				else if (item.getSex().equals("Nữ"))
					female++;
			int count = 0;
			int totalUserByMonth = 0;

			while (arrEachMonth.size() < 12) {
				count++;
				int totalEachMonth = 0;
				int totalUserByMonthInLastYear = 0;
				for (User item: userListAll)
					if (Integer.parseInt(item.getCreatedAt().toString().substring(5,7)) == count && Integer.parseInt(item.getCreatedAt().toString().substring(0,4)) == localDate.getYear())
						totalEachMonth++;
					else if (Integer.parseInt(item.getCreatedAt().toString().substring(5,7)) == count && Integer.parseInt(item.getCreatedAt().toString().substring(0,4)) == (localDate.getYear()-1))
						totalUserByMonthInLastYear++;
				totalUserByMonth += totalEachMonth;
				arr.add(totalUserByMonth);
				arrEachMonth.add(totalEachMonth);
				arrEachMonthInLastYear.add(totalUserByMonthInLastYear);
			}
			req.setAttribute("arrEachMonth", arrEachMonth);
			req.setAttribute("arrEachMonthInLastYear", arrEachMonthInLastYear);
			req.setAttribute("arrByMonth", arr);
			req.setAttribute("total", total);
			req.setAttribute("male", male);
			req.setAttribute("female", female);
			req.setAttribute("userList", userList);
			req.getRequestDispatcher("/views/admin/user/closest.jsp").forward(req, resp);
		}

	}

	protected void usersPage(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		req.setCharacterEncoding("UTF-8");
		resp.setCharacterEncoding("UTF-8");
		int totalItemInPage = TOTAL_ITEM_IN_PAGE;
		String indexPage = req.getParameter("index");
		String searchKey = req.getParameter("search");
		if(indexPage == null) {
			indexPage = "1";
		}
		int countP = userService.count(searchKey);
		int endP = (countP/totalItemInPage);
		if (countP % totalItemInPage != 0) {
			endP ++;
		}
		Pageble pageble = new PageRequest(Integer.parseInt(indexPage), totalItemInPage, null);
		List<User> userList = userService.findAll(pageble, searchKey);
		req.setAttribute("userList", userList);
		req.setAttribute("countP", countP);
		req.setAttribute("endP", endP);
		req.setAttribute("tag", indexPage);
		req.setAttribute("totalItemInPage", totalItemInPage);
		req.setAttribute("search", searchKey);
	}

}
