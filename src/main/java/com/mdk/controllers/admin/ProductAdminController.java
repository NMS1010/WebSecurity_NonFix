package com.mdk.controllers.admin;

import static com.mdk.utils.AppConstant.TOTAL_ITEM_IN_PAGE;

import java.io.IOException;
import java.util.List;
import java.util.Properties;

import javax.mail.Message;
import javax.mail.PasswordAuthentication;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.mdk.models.Category;
import com.mdk.models.Product;
import com.mdk.paging.PageRequest;
import com.mdk.paging.Pageble;
import com.mdk.services.ICategoryService;
import com.mdk.services.IProductService;
import com.mdk.services.impl.CategoryService;
import com.mdk.services.impl.ProductService;

@WebServlet(urlPatterns = {"/admin/product/permit", "/admin/product/prohibit", "/admin/product/category", "/admin/product/category/add", "/admin/product/category/edit", "/admin/product/category/delete-soft", "/admin/product/category/delete", "/admin/product/category/restore", "/admin/product/ban"})
public class ProductAdminController extends HttpServlet{

    private static final long serialVersionUID = 1L;
    ICategoryService categoryService = new CategoryService();
    IProductService productService = new ProductService();
    
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String url = req.getRequestURL().toString();
        if (url.contains("product/ban")) {
            String productId = req.getParameter("productId");
            String state = req.getParameter("state");
            productService.ban(Integer.parseInt(productId), Boolean.parseBoolean(state));
            if (state.equals("true")) {
                resp.sendRedirect(req.getContextPath() + "/admin/product/prohibit");
            } else {
                resp.sendRedirect(req.getContextPath() + "/admin/product/permit");
            }
            sendEmail(req, resp, productId, state);
        }
        else if (url.contains("product/category/edit")) {
            String id = req.getParameter("id");
            Category category = categoryService.findById(Integer.parseInt(id));
            req.setAttribute("category", category);
            req.getRequestDispatcher("/views/admin/product/category/edit.jsp").forward(req, resp);
        }
        else if (url.contains("product/category/add")) {
            req.getRequestDispatcher("/views/admin/product/category/add.jsp").forward(req, resp);
        }
        else if (url.contains("product/category/delete-soft")) {
            String id = req.getParameter("id");
            categoryService.deleteSoft(Integer.parseInt(id));
            resp.sendRedirect(req.getContextPath() + "/admin/product/category");
        }
        else if (url.contains("product/category/delete")) {
            String id = req.getParameter("id");
            categoryService.delete(Integer.parseInt(id));
            resp.sendRedirect(req.getContextPath() + "/admin/product/category");
        }
        else if (url.contains("product/category/restore")) {
            String id = req.getParameter("id");
            categoryService.restore(Integer.parseInt(id));
            resp.sendRedirect(req.getContextPath() + "/admin/product/category?state=true");
        }
        else if (url.contains("product/category")) {
            categoryPage(req, resp);
            req.getRequestDispatcher("/views/admin/product/category/index.jsp").forward(req, resp);
        }
        else if (url.contains("product/permit")) {
            productsPage(req, resp, "true");
            req.getRequestDispatcher("/views/admin/product/permit.jsp").forward(req, resp);
        }
        else if (url.contains("product/prohibit")) {
            productsPage(req, resp, "false");
            req.getRequestDispatcher("/views/admin/product/prohibit.jsp").forward(req, resp);
        }
    }
    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String url = req.getRequestURL().toString();
        resp.setContentType("text/html;charset=UTF-8");
        resp.setCharacterEncoding("UTF-8");
        req.setCharacterEncoding("UTF-8");
        if (url.contains("product/category/add")) {
            Category category = new Category();
            try {
                category.setName(req.getParameter("name"));
                categoryService.insert(category);
                resp.sendRedirect(req.getContextPath() + "/admin/product/category");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        else if (url.contains("product/category/edit")) {
            Category category = new Category();
            try {
                category.setId(Integer.valueOf(req.getParameter("id")));
                category.setName(req.getParameter("name"));
                categoryService.edit(category);
                resp.sendRedirect(req.getContextPath() + "/admin/product/category");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    protected void productsPage(HttpServletRequest req, HttpServletResponse resp, String status) throws ServletException, IOException {
        req.setCharacterEncoding("UTF-8");
        resp.setCharacterEncoding("UTF-8");
        int totalItemInPage = TOTAL_ITEM_IN_PAGE;
        String indexPage = req.getParameter("index");
        String keyword = req.getParameter("search");
        int storeId = req.getParameter("storeId") == null ? 0 : Integer.parseInt(req.getParameter("storeId"));

        if(indexPage == null) {
            indexPage = "1";
        }
        int countP = productService.count(status, storeId, keyword);
        int endP = (countP/totalItemInPage);
        if (countP % totalItemInPage != 0) {
            endP ++;
        }

        Pageble pageble = new PageRequest(Integer.parseInt(indexPage), totalItemInPage, null);
        List<Product> productList = productService.findAll(pageble, status, storeId, keyword);
        req.setAttribute("productList", productList);
        req.setAttribute("countP", countP);
        req.setAttribute("endP", endP);
        req.setAttribute("tag", indexPage);
        req.setAttribute("totalItemInPage", totalItemInPage);
        req.setAttribute("search", keyword);
    }

    protected void categoryPage(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException{
        int totalItemInPage = TOTAL_ITEM_IN_PAGE;
        String indexPage = req.getParameter("index");
        String keyword = req.getParameter("search");
        if(indexPage == null) {
            indexPage = "1";
        }
        String state = req.getParameter("state") == null ? "false" : req.getParameter("state");
        int countP = categoryService.count(state, keyword);
        int endP = (countP/totalItemInPage);
        if (countP % totalItemInPage != 0) {
            endP ++;
        }

        Pageble pageble = new PageRequest(Integer.parseInt(indexPage), totalItemInPage, null);
        List<Category> categories = categoryService.findAll(pageble, state, keyword);
        req.setAttribute("state", state);
        req.setAttribute("countP", countP);
        req.setAttribute("totalItemInPage", totalItemInPage);
        req.setAttribute("endP", endP);
        req.setAttribute("tag", indexPage);
        req.setAttribute("categories", categories);
        req.setAttribute("search", keyword);
    }

    protected void sendEmail(HttpServletRequest req, HttpServletResponse resp, String productId, String state) throws ServletException, IOException {
        String email = productService.findOwnerEmailByProductId(Integer.parseInt(productId));
        Product product = productService.findOneById(Integer.parseInt(productId));
        resp.setContentType("text/html");

        String subject = "", img = "", mainTitle = "", subTitle = "";
        if (state.equals("true")) {
            subject = "Sản phẩm bị cấm được mở bán";
            img = "https://img.freepik.com/free-vector/shop-with-we-are-open-sign_23-2148557016.jpg";
            mainTitle = "MỞ BÁN";
            subTitle = "Sau khi hệ thống xem xét lại tiêu chuẩn cộng động, hệ thống xin chúc mừng cửa hàng cửa bạn được mở bán lại 01 sản phẩm.";
        } else {
            subject = "Sản phẩm bị cấm";
            img = "https://st.depositphotos.com/1064545/2274/i/600/depositphotos_22745337-stock-photo-3d-white-forbidden-sign.jpg";
            mainTitle = "CẤM BÁN";
            subTitle = "Bạn có một sản phẩm đã bị cấm bán do vi phạm tiêu chuẩn cộng đồng của hệ thống.";
        }


        final String username = "0509dangle@gmail.com";
        final String password = "pmvcktmweazmgsqt";
        Properties props = new Properties();
        props.put("mail.smtp.auth", true);
        props.put("mail.smtp.starttls.enable", true);
        props.put("mail.smtp.host", "smtp.gmail.com");
        props.put("mail.smtp.port", "587");
        Session session = Session.getInstance(props,
                new javax.mail.Authenticator() {
                    @Override
                    protected PasswordAuthentication getPasswordAuthentication() {
                        return new PasswordAuthentication(username, password);
                    }
                });
        try {
            MimeMessage message = new MimeMessage(session);
            message.setFrom(new InternetAddress(username));
            message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(email));
            message.setSubject(subject, "utf-8");
            String htmlContent = " <table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\">\n" +
                    "        <tr>\n" +
                    "            <td bgcolor=\"#FFA73B\" align=\"center\">\n" +
                    "                <table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\" style=\"max-width: 600px;\">\n" +
                    "                    <tr>\n" +
                    "                        <td align=\"center\" valign=\"top\" style=\"padding: 40px 10px 40px 10px;\"> </td>\n" +
                    "                    </tr>\n" +
                    "                </table>\n" +
                    "            </td>\n" +
                    "        </tr>\n" +
                    "        <tr>\n" +
                    "            <td bgcolor=\"#FFA73B\" align=\"center\" style=\"padding: 0px 10px 0px 10px;\">\n" +
                    "                <table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\" style=\"max-width: 600px;\">\n" +
                    "                    <tr>\n" +
                    "                        <td bgcolor=\"#ffffff\" align=\"center\" valign=\"top\"\n" +
                    "                            style=\"padding: 40px 20px 20px 20px; border-radius: 4px 4px 0px 0px; color: #111111; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 48px; font-weight: 400; letter-spacing: 4px; line-height: 48px;\">\n" +
                    "                            <h1 style=\"font-size: 48px; font-weight: 400; margin: 2;\">"+mainTitle+"</h1> <img\n" +
                    "                                src=\""+img+"\"\n" +
                    "                                width=\"200\" height=\"200\" style=\"display: block; border: 0px;\" />\n" +
                    "                        </td>\n" +
                    "                    </tr>\n" +
                    "                </table>\n" +
                    "            </td>\n" +
                    "        </tr>\n" +
                    "        <tr>\n" +
                    "            <td bgcolor=\"#f4f4f4\" align=\"center\" style=\"padding: 0px 10px 0px 10px;\">\n" +
                    "                <table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\" style=\"max-width: 600px;\">\n" +
                    "                    <tr>\n" +
                    "                        <td bgcolor=\"#ffffff\" align=\"left\"\n" +
                    "                            style=\"padding: 0px 30px 20px 30px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px; font-weight: 400; line-height: 25px;\">\n" +
                    "                            <p style=\"margin: 0;\">"+subTitle+"</p>\n" +
                    "                        </td>\n" +
                    "                    </tr>\n" +
                    "                    <tr>\n" +
                    "                        <td bgcolor=\"#ffffff\" align=\"left\"\n" +
                    "                            style=\"padding: 0px 30px 20px 30px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px; font-weight: 400; line-height: 25px;\">\n" +
                    "                            <p style=\"margin: 0;\">Thông tin sản phẩm:</p>\n" +
                    "                            <ul>\n" +
                    "                                <li>Tên: "+product.getName()+".</li>\n" +
                    "                                <li>Giá: "+product.getPrice()+" đồng.</li>\n" +
                    "                            </ul>\n" +
                    "                        </td>\n" +
                    "                    </tr>\n" +
                    "                    <tr>\n" +
                    "                        <td bgcolor=\"#ffffff\" align=\"left\"\n" +
                    "                            style=\"padding: 0px 30px 20px 30px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px; font-weight: 400; line-height: 25px;\">\n" +
                    "                            <p style=\"margin: 0;\">Nếu có bất kì phản hồi nào xin vui\n" +
                    "                                lòng liên hệ vào địa chỉ email sau: <span\n" +
                    "                                    style=\"font-weight: 700; font-style: italic;\">0509dangle@gmail.com</span> .</p>\n" +
                    "                        </td>\n" +
                    "                    </tr>\n" +
                    "                    <tr>\n" +
                    "                        <td bgcolor=\"#ffffff\" align=\"left\"\n" +
                    "                            style=\"padding: 0px 30px 40px 30px; border-radius: 0px 0px 4px 4px; color: #666666; font-family: 'Lato', Helvetica, Arial, sans-serif; font-size: 18px; font-weight: 400; line-height: 25px;\">\n" +
                    "                            <p style=\"margin: 0;\">Chào bạn,<br>MDK</p>\n" +
                    "                        </td>\n" +
                    "                    </tr>\n" +
                    "                </table>\n" +
                    "            </td>\n" +
                    "        </tr>\n" +
                    "    </table>";
            message.setContent(htmlContent, "text/html;charset=utf-8");
            Transport.send(message);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
