package com.mdk.controllers.vendor;

import static com.mdk.controllers.vendor.CheckStoreExist.checkStoreExist;

import java.io.IOException;
import java.time.LocalDate;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.mdk.models.Orders;
import com.mdk.models.Store;
import com.mdk.services.IOrdersService;
import com.mdk.services.IProductService;
import com.mdk.services.IStoreService;
import com.mdk.services.impl.OrdersService;
import com.mdk.services.impl.ProductService;
import com.mdk.services.impl.StoreService;
import com.mdk.utils.MessageUtil;
import com.mdk.utils.SessionUtil;

@WebServlet(urlPatterns = {"/vendor/statistic", "/vendor/statistic/notification"})
public class StatisticVendorController extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	IStoreService storeService = new StoreService();
    IProductService productService = new ProductService();
    IOrdersService ordersService = new OrdersService();
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String url = req.getRequestURL().toString();
        if (url.contains("notification")) {
            MessageUtil.showMessage(req, resp);
            req.getRequestDispatcher("/views/vendor/statistic.jsp").forward(req, resp);
        } else if (url.contains("statistic")){
            if (checkStoreExist(req, resp)) {
                Store store = (Store) SessionUtil.getInstance().getValue(req, "STORE");
                mainStatistic(req, resp, store);
                req.getRequestDispatcher("/views/vendor/statistic.jsp").forward(req, resp);
            } else {
                resp.sendRedirect(req.getContextPath() + "/vendor/statistic/notification?message=nostore_error");
            }
        }
    }
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        // TODO Auto-generated method stub
        super.doPost(req, resp);
    }
    protected void mainStatistic(HttpServletRequest req, HttpServletResponse resp, Store store) throws ServletException,
            IOException {
        totalCustomer(req, resp, store);
        totalProduct(req, resp, store);
        totalOrder(req, resp, store);
        totalSale(req, resp, store);
        topSeller(req, resp, store);
        ordersNew(req, resp, store);
        chartRevenue(req, resp, store);
    }
    protected void totalCustomer(HttpServletRequest req, HttpServletResponse resp, Store store) throws ServletException,
            IOException {
        int totalCustomer = storeService.totalCustomer(store.getId());
        req.setAttribute("totalCustomer", totalCustomer);
    }
    protected void totalProduct(HttpServletRequest req, HttpServletResponse resp, Store store) throws ServletException,
            IOException {
        int totalProduct = storeService.totalProduct(store.getId());
        req.setAttribute("totalProduct", totalProduct);
    }
    protected void totalOrder(HttpServletRequest req, HttpServletResponse resp, Store store) throws ServletException,
            IOException {
        int totalOrder = storeService.totalOrders(store.getId());
        req.setAttribute("totalOrder", totalOrder);
    }
    protected void totalSale(HttpServletRequest req, HttpServletResponse resp, Store store) throws ServletException,
            IOException {
        int totalSale = storeService.totalSale(store.getId());
        req.setAttribute("totalSale", totalSale);
    }
    protected void topSeller(HttpServletRequest req, HttpServletResponse resp, Store store) throws ServletException,
            IOException {
        int top = req.getParameter("top") == null ? 4 : Integer.parseInt(req.getParameter("top"));
        req.setAttribute("top", top);
    }
    protected void ordersNew(HttpServletRequest req, HttpServletResponse resp, Store store) throws ServletException, IOException {
        List<Orders> orders = ordersService.ordersNew(store.getId());
        req.setAttribute("orders", orders);
    }
    protected void chartRevenue(HttpServletRequest req, HttpServletResponse resp, Store store) throws ServletException, IOException {
        LocalDate localDate = LocalDate.now();
        int year = localDate.getYear();
        req.setAttribute("year", year);
    }
}
