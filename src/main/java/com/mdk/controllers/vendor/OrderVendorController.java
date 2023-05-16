package com.mdk.controllers.vendor;

import static com.mdk.controllers.vendor.CheckStoreExist.checkStoreExist;
import static com.mdk.utils.AppConstant.TOTAL_ITEM_IN_PAGE;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.mdk.models.Orders;
import com.mdk.models.OrdersDetail;
import com.mdk.models.Store;
import com.mdk.paging.PageRequest;
import com.mdk.paging.Pageble;
import com.mdk.services.IOrdersDetailService;
import com.mdk.services.IOrdersService;
import com.mdk.services.impl.OrdersDetailService;
import com.mdk.services.impl.OrdersService;
import com.mdk.utils.MessageUtil;
import com.mdk.utils.SessionUtil;

@WebServlet(urlPatterns = {"/vendor/order", "/vendor/order/manager", "/vendor/order/detail", "/vendor/order/update"})
public class OrderVendorController extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	IOrdersService ordersService = new OrdersService();
    IOrdersDetailService ordersDetailService = new OrdersDetailService();
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.setCharacterEncoding("UTF-8");
        resp.setCharacterEncoding("UTF-8");
        String url = req.getRequestURL().toString();
        if (url.contains("manager")){
            if (checkStoreExist(req, resp)) {
                ordersPage(req, resp);
                req.getRequestDispatcher("/views/vendor/managerOrder.jsp").forward(req, resp);
            } else {
                resp.sendRedirect(req.getContextPath() + "/vendor/order?message=nostore_error");
            }
        } else if (url.contains("detail")) {
            orderDetail(req, resp);
            req.getRequestDispatcher("/views/vendor/order.jsp").forward(req, resp);
        }
        else {
            if (checkStoreExist(req, resp)) {
                ordersPage(req, resp);
            }
            req.setAttribute("success", req.getParameter("state"));
            MessageUtil.showMessage(req, resp);
            req.getRequestDispatcher("/views/vendor/managerOrder.jsp").forward(req, resp);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.setCharacterEncoding("UTF-8");
        resp.setCharacterEncoding("UTF-8");
        String url = req.getRequestURL().toString();
        if (url.contains("update")) {
            updateStatusOrder(req, resp);
            resp.sendRedirect(req.getContextPath() + "/vendor/order?status=all&message=update_success");
        }
    }

    protected void ordersPage(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.setCharacterEncoding("UTF-8");
        resp.setCharacterEncoding("UTF-8");
        String dateStart = req.getParameter("start");
        String dateEnd = req.getParameter("end");

        String statusReq = req.getParameter("status") == null ? "all" : req.getParameter("status");
        Store store = (Store) SessionUtil.getInstance().getValue(req, "STORE");

        int totalItemInPage = TOTAL_ITEM_IN_PAGE;
        String indexPage = req.getParameter("index");
        if(indexPage == null) {
            indexPage = "1";
        }

        int countP = ordersService.count(statusReq, store.getId(), dateStart, dateEnd);
        int endP = (countP/totalItemInPage);
        if (countP % totalItemInPage != 0) {
            endP ++;
        }

        Pageble pageble = new PageRequest(Integer.parseInt(indexPage), totalItemInPage, null);
        List<Orders> ordersList = ordersService.findAll(statusReq, pageble, store.getId(), dateStart, dateEnd);
        req.setAttribute("orders", ordersList);
        req.setAttribute("count", countP);
        req.setAttribute("endP", endP);
        req.setAttribute("tag", indexPage);
        req.setAttribute("statusResp",statusReq);
        req.setAttribute("dateStart", dateStart);
        req.setAttribute("dateEnd", dateEnd);
    }
    protected void orderDetail(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException{
        req.setCharacterEncoding("UTF-8");
        resp.setCharacterEncoding("UTF-8");
        int orderId = Integer.parseInt(req.getParameter("orderId"));
        OrdersDetail ordersDetail = ordersDetailService.findOrderDetailById(orderId);
        req.setAttribute("ordersDetail", ordersDetail);
    }

    protected void updateStatusOrder(HttpServletRequest req, HttpServletResponse resp) throws ServletException,
            IOException {
        req.setCharacterEncoding("UTF-8");
        resp.setCharacterEncoding("UTF-8");
        String statusResp = req.getParameter("status");

        int orderId = Integer.parseInt(req.getParameter("orderId"));
        ordersService.updateStatus(statusResp, orderId);
    }
}
