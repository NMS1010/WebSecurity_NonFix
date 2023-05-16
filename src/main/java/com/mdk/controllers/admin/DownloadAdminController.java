package com.mdk.controllers.admin;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.PrintWriter;
@WebServlet(urlPatterns = "/admin/download-report")
public class DownloadAdminController extends HttpServlet {
    private static final long serialVersionUID = 1L;

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String type = req.getParameter("type");;
        String filename = "", sendRedirect = "";
        if (type.equals("user")) {
            filename = "reportUser.xls";
            sendRedirect = "/admin/user/all";
        } else if (type.equals("store")){
            filename = "reportStore.xls";
            sendRedirect = "/admin/store";
        } else if (type.equals("order")){
            filename = "reportOrder.xls";
            sendRedirect = "/admin/order?state=delivered";
        } else if (type.equals("transaction")) {
            filename = "reportTransaction.xls";
            sendRedirect = "/admin/transaction";
        }

        resp.setContentType("text/html");
        PrintWriter out = resp.getWriter();
        String path = "E:\\";
        resp.setContentType("APPLICATION/OCTET-STREAM");
        resp.setHeader("Content-Disposition", "attachment; filename=\"" + filename + "\"");

        FileInputStream fileInputStream = new FileInputStream(path + filename);

        int i;
        while ((i = fileInputStream.read()) != -1) {
            out.write(i);
        }
        fileInputStream.close();
        out.close();
        resp.sendRedirect(req.getContextPath() + sendRedirect);
    }
}
