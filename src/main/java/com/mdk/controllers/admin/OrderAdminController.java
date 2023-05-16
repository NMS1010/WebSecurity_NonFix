package com.mdk.controllers.admin;


import static com.mdk.utils.AppConstant.TOTAL_ITEM_IN_PAGE;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.mdk.models.OrderDetails;
import com.mdk.models.Orders;
import com.mdk.models.Store;
import com.mdk.paging.PageRequest;
import com.mdk.paging.Pageble;
import com.mdk.services.IOrdersService;
import com.mdk.services.IStoreService;
import com.mdk.services.impl.OrdersService;
import com.mdk.services.impl.StoreService;
import com.mdk.utils.ExportExcel;

@WebServlet(urlPatterns = {"/admin/order", "/admin/order/details"})
public class OrderAdminController extends HttpServlet{

    private static final long serialVersionUID = 1L;
    IOrdersService ordersService = new OrdersService();
    IStoreService storeService = new StoreService();
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String url = req.getRequestURL().toString();

        if (url.contains("admin/order/details")) {
            String id = req.getParameter("id");
            List<OrderDetails> orderDetailsList = ordersService.findDetailByOrderId(Integer.valueOf(id));
            Orders orders = ordersService.findOneById(Integer.valueOf(id));
            req.setAttribute("orders", orders);
            req.setAttribute("orderDetailsList", orderDetailsList);
            req.getRequestDispatcher("/views/admin/order/details.jsp").forward(req, resp);
        }
        else if (url.contains("admin/order")) {
            orderPage(req, resp);
            List<Orders> ordersList = ordersService.findAllForReport();
            final String excelFilePath = "E:\\reportOrder.xls";
            ExportExcel.writeExcel(ordersList, excelFilePath, Orders.getColumns(), "reportOrder");
            if (req.getParameter("state").equals("delivered")) {
                req.getRequestDispatcher("/views/admin/order/index.jsp").forward(req, resp);
            } else {
                req.getRequestDispatcher("/views/admin/order/shipped.jsp").forward(req, resp);

            }
        }
    }
    protected void orderPage(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException{
        int totalItemInPage = TOTAL_ITEM_IN_PAGE;
        String indexPage = req.getParameter("index");
        String keyword = req.getParameter("search");
        if(indexPage == null) {
            indexPage = "1";
        }
        String state = req.getParameter("state") == null ? "delivered" : req.getParameter("state");
        List<Store> storesList = storeService.findAll();
        int storeId = req.getParameter("storeId") == null ? storesList.get(0).getId() : Integer.parseInt(req.getParameter("storeId"));

        int countP = ordersService.countByStoreId(state, storeId, keyword);
        int endP = (countP/totalItemInPage);
        if (countP % totalItemInPage != 0) {
            endP ++;
        }

        Pageble pageble = new PageRequest(Integer.parseInt(indexPage), totalItemInPage, null);
        List<Orders> ordersList = ordersService.findAllByStoreId(state, storeId, pageble, keyword);
        for (Orders item: ordersList
             ) {
            item.setNameOwner(item.getUser().getLastname() + " " + item.getUser().getFirstname());
            item.setNameDelivery(item.getDelivery().getName());
        }
        req.setAttribute("state", state);
        req.setAttribute("storeId", storeId);
        req.setAttribute("storesList", storesList);
        req.setAttribute("countP", countP);
        req.setAttribute("totalItemInPage", totalItemInPage);
        req.setAttribute("endP", endP);
        req.setAttribute("tag", indexPage);
        req.setAttribute("ordersList", ordersList);
        req.setAttribute("search", keyword);
    }
}
