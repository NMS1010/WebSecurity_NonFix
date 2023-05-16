package com.mdk.controllers.admin;

import com.mdk.models.Delivery;
import com.mdk.paging.PageRequest;
import com.mdk.paging.Pageble;
import com.mdk.services.IDeliveryService;
import com.mdk.services.impl.DeliveryService;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static com.mdk.utils.AppConstant.TOTAL_ITEM_IN_PAGE;

@WebServlet(urlPatterns = {"/admin/delivery", "/admin/delivery/add", "/admin/delivery/edit", "/admin/delivery/delete-soft", "/admin/delivery/restore", "/admin/delivery/delete"})
public class DeliveryAdminController extends HttpServlet{

    private static final long serialVersionUID = 1L;
    IDeliveryService deliveryService = new DeliveryService();
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String url = req.getRequestURL().toString();
        resp.setContentType("text/html;charset=UTF-8");
        if (url.contains("delivery/add")) {
            req.getRequestDispatcher("/views/admin/delivery/add.jsp").forward(req, resp);
        }
        else if (url.contains("delivery/edit")) {
            String id = req.getParameter("id");
            Delivery delivery = deliveryService.findById(Integer.parseInt(id));
            req.setAttribute("delivery", delivery);
            req.getRequestDispatcher("/views/admin/delivery/edit.jsp").forward(req, resp);
        }
        else if (url.contains("delivery/delete-soft")) {
            String id = req.getParameter("id");
            deliveryService.deleteSoft(Integer.parseInt(id));
            resp.sendRedirect(req.getContextPath() + "/admin/delivery");
        }
        else if (url.contains("delivery/restore")) {
            String id = req.getParameter("id");
            deliveryService.restore(Integer.parseInt(id));
            resp.sendRedirect(req.getContextPath() + "/admin/delivery?state=true");
        }
        else if (url.contains("delivery/delete")) {
            String id = req.getParameter("id");
            deliveryService.delete(Integer.parseInt(id));
            resp.sendRedirect(req.getContextPath() + "/admin/delivery");
        }

        else if (url.contains("delivery")) {
            deliveryPage(req, resp);
            req.getRequestDispatcher("/views/admin/delivery/index.jsp").include(req, resp);
        }


    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String url = req.getRequestURL().toString();
        resp.setContentType("text/html;charset=UTF-8");
        resp.setCharacterEncoding("UTF-8");
        req.setCharacterEncoding("UTF-8");
        if (url.contains("delivery/add")) {
            Delivery delivery = new Delivery();
            try {
                delivery.setName(req.getParameter("name"));
                delivery.setDescription(req.getParameter("description"));
                delivery.setPrice(Double.valueOf(req.getParameter("price")));
                deliveryService.insert(delivery);
                resp.sendRedirect(req.getContextPath() + "/admin/delivery");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        else if (url.contains("delivery/edit")) {
            Delivery delivery = new Delivery();
            try {
                delivery.setId(Integer.valueOf(req.getParameter("id")));
                delivery.setName(req.getParameter("name"));
                delivery.setDescription(req.getParameter("description"));
                delivery.setPrice(Double.valueOf(req.getParameter("price")));
                deliveryService.edit(delivery);
                resp.sendRedirect(req.getContextPath() + "/admin/delivery");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
    protected void deliveryPage(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException{
        int totalItemInPage = TOTAL_ITEM_IN_PAGE;
        String indexPage = req.getParameter("index");
        String keyword = req.getParameter("search");
        if(indexPage == null) {
            indexPage = "1";
        }
        String state = req.getParameter("state") == null ? "false" : req.getParameter("state");
        int countP = deliveryService.count(state, keyword);
        int endP = (countP/totalItemInPage);
        if (countP % totalItemInPage != 0) {
            endP ++;
        }

        Pageble pageble = new PageRequest(Integer.parseInt(indexPage), totalItemInPage, null);
        List<Delivery> deliveries = deliveryService.findAll(pageble, state, keyword);

        req.setAttribute("state", state);
        req.setAttribute("countP", countP);
        req.setAttribute("totalItemInPage", totalItemInPage);
        req.setAttribute("endP", endP);
        req.setAttribute("tag", indexPage);
        req.setAttribute("deliveries", deliveries);
        req.setAttribute("search", keyword);
    }
}
