package com.mdk.controllers.vendor;

import com.mdk.models.Product;
import com.mdk.models.Store;
import com.mdk.services.IProductService;
import com.mdk.services.impl.ProductService;
import com.mdk.utils.SessionUtil;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;

import static com.mdk.utils.AppConstant.STORE_MODEL;

@WebServlet(urlPatterns = "/vendor/loadTopProduct")
public class LoadTopProduct extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	@Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setCharacterEncoding("UTF-8");

        IProductService productService = new ProductService();
        Store store = (Store) SessionUtil.getInstance().getValue(req, STORE_MODEL);

        int top = req.getParameter("top") == null ? 4 : Integer.parseInt(req.getParameter("top"));
        List<Product> products = productService.topSeller(store.getId(), top);

        PrintWriter out = resp.getWriter();
        for (Product o : products) {
            StringBuilder rating = new StringBuilder("");
            for (int i = 1; i <= 5; i++) {
                if (i <= o.getRating()) {
                    rating.append("<i class=\"fa fa-star\"></i>");
                } else {
                    rating.append("<i class=\"fa fa-star-o\"></i>");
                }
            }
            String urlImage = req.getContextPath() + "/image?fname="+o.getImages().get(0).getName()+"&type=product";
            String urlView = req.getContextPath() + "/vendor/product/edit?pname="+o.getName()+"&storeId="+o.getStoreId();
            out.println("<div class=\"product col-sm-6 col-md-4 col-lg-3\">\n" +
                    "                                    <div class=\"iq-card iq-card-block iq-card-stretch iq-card-height browse-bookcontent\">\n" +
                    "                                        <div class=\"iq-card-body p-0\">\n" +
                    "                                            <div>\n" +
                    "                                                <div class=\"col-12 p-0 position-relative image-overlap-shadow\"\n" +
                    "                                                     style=\"height: 150px;\">\n" +
                    "                                                    <a href=\"\">\n" +
                    "                                                        <c:url value=\"/image?fname=${product.getImages().get(0).getName()}&type=product\"\n" +
                    "                                                               var=\"imgUrl\"></c:url>\n" +
                    "                                                        <img class=\"img-fluid rounded w-100 h-100\"\n" +
                    "                                                             style=\"object-fit: contain;\"\n" +
                    "                                                             src=\""+urlImage+"\"\n" +
                    "                                                             alt=\"\">\n" +
                    "                                                    </a>\n" +
                    "                                                    <div class=\"view-book\">\n" +
                    "                                                        <a href=\""+urlView+"\"\n" +
                    "                                                           class=\"btn btn-sm btn-white\">\n" +
                    "                                                            View Book\n" +
                    "                                                        </a>\n" +
                    "                                                    </div>\n" +
                    "                                                </div>\n" +
                    "                                                <div class=\"col-12 mt-3\">\n" +
                    "                                                    <div class=\"mb-2\">\n" +
                    "                                                        <h6 class=\"mb-1\">"+o.getName()+"</h6>\n" +
                    "                                                        <p class=\"font-size-13 line-height " +
                    "mb-1\">"+o.getDescription()+"</p>\n" +
                    "                                                        <div class=\"d-block line-height\">\n" +
                    "                                                   <span class=\"font-size-11 text-warning\">\n" +
                                                                            rating +
                    "                                                   </span>\n" +
                    "                                                        </div>\n" +
                    "                                                    </div>\n" +
                    "                                                    <div class=\"price d-flex\">\n" +
                    "                                                         <span class=\"pr-1 old-price " +
                    "font-size-13\">"+o.getPrice()+"</span>\n" +
                    "                                                        <br>\n" +
                    "                                                        <h6><b>"+o.getPromotionalPrice()+"</b></h6>\n" +
                    "                                                    </div>\n" +
                    "                                                </div>\n" +
                    "                                            </div>\n" +
                    "                                        </div>\n" +
                    "                                    </div>\n" +
                    "                                </div>");
        }
    }
}
