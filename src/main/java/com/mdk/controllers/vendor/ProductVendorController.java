package com.mdk.controllers.vendor;

import com.mdk.models.*;
import com.mdk.paging.PageRequest;
import com.mdk.paging.Pageble;
import com.mdk.services.ICategoryService;
import com.mdk.services.IImageProductService;
import com.mdk.services.IProductService;
import com.mdk.services.impl.CategoryService;
import com.mdk.services.impl.ImageProductService;
import com.mdk.services.impl.ProductService;
import com.mdk.utils.DeleteImageUtil;
import com.mdk.utils.SessionUtil;
import com.mdk.utils.UploadUtil;

import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Part;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import static com.mdk.controllers.vendor.CheckStoreExist.checkStoreExist;
import static com.mdk.utils.AppConstant.*;
import static com.mdk.utils.MessageUtil.showMessage;

@MultipartConfig(fileSizeThreshold = 1024 * 1024 * 10, // 10MB
        maxFileSize = 1024 * 1024 * 50, // 50MB
        maxRequestSize = 1024 * 1024 * 50) // 50MB
@WebServlet(urlPatterns = {"/vendor/product", "/vendor/product/create", "/vendor/product/edit",
        "/vendor/product/delete", "/vendor/product/category"})
public class ProductVendorController extends HttpServlet {
    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	ICategoryService categoryService = new CategoryService();
    IProductService productService = new ProductService();
    IImageProductService imageProductService = new ImageProductService();
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String url = req.getRequestURL().toString();
        if(url.contains("create")) {
            if (checkStoreExist(req, resp)) {
                loadCategory(req, resp);
                req.setAttribute("action", "add");
                req.getRequestDispatcher("/views/vendor/product.jsp").forward(req, resp);
            } else {
                resp.sendRedirect(req.getContextPath() + "/vendor/product/category?message=nostore_error");
            }
        } else if (url.contains("edit")) {
            loadCategory(req, resp);
            findOneByName(req, resp);
            req.setAttribute("action", "edit");
            req.getRequestDispatcher("/views/vendor/product.jsp").forward(req, resp);
        } else if (url.contains("delete")) {
            delete(req, resp);
        } else if (url.contains("category")) {
            if (checkStoreExist(req, resp)) {
                productPage(req, resp);
            }
            showMessage(req, resp);
            req.getRequestDispatcher("/views/vendor/listProduct.jsp").forward(req, resp);
        }
        else {
            if (checkStoreExist(req, resp)) {
                productPage(req, resp);
            }
            showMessage(req, resp);
            req.getRequestDispatcher("/views/vendor/listProduct.jsp").forward(req, resp);
        }
    }

    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String url = req.getRequestURL().toString();
        if (url.contains("create")){
            try {
                insert(req, resp);
                resp.sendRedirect(req.getContextPath() + "/vendor/product?message=insert_success");
            } catch (Exception e) {
                resp.sendRedirect(req.getContextPath() + "/vendor/product?message=" + e.getMessage());
            }
        } else if (url.contains("edit")) {
            try {
                update(req, resp);
                resp.sendRedirect(req.getContextPath() + "/vendor/product?message=update_success");
            } catch (Exception e) {
                resp.sendRedirect(req.getContextPath() + "/vendor/product?message=" + e.getMessage());
            }
        }
    }
    protected void productPage(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException{
        int totalItemInPage = TOTAL_ITEM_IN_PAGE;
        Store store = (Store) SessionUtil.getInstance().getValue(req, STORE_MODEL);
        String indexPage = req.getParameter("index");
        String searchKey = req.getParameter("search");
        if(indexPage == null) {
            indexPage = "1";
        }
        int categoryId = req.getParameter("categoryId") == null ? 0 : Integer.parseInt(req.getParameter("categoryId"));
        int countP = productService.count(categoryId, store.getId(), searchKey);
        int endP = (countP/totalItemInPage);
        if (countP % totalItemInPage != 0) {
            endP ++;
        }

        Pageble pageble = new PageRequest(Integer.parseInt(indexPage), totalItemInPage, null);
        List<Product> products = new ArrayList<>();
        products = productService.findAll(pageble, categoryId, store.getId(), searchKey);
        loadCategory(req, resp);
        req.setAttribute("categoryId", categoryId);
        req.setAttribute("count", countP);
        req.setAttribute("total", totalItemInPage);
        req.setAttribute("endP", endP);
        req.setAttribute("tag", indexPage);
        req.setAttribute("DIR", UPLOAD_PRODUCT_DIRECTORY);
        req.setAttribute("products", products);
        req.setAttribute("search", searchKey);
    }
    protected void findOneByName(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException{
        String pname = req.getParameter("pname");
        int storeId = Integer.valueOf(req.getParameter("storeId"));
        Product product = productService.findOneByName(pname, storeId);
        List<ImageProduct> images = imageProductService.findByProductId(product.getId());
        req.setAttribute("DIR", UPLOAD_PRODUCT_DIRECTORY);
        req.setAttribute("product", product);
        req.setAttribute("images", images);
    }
    protected void loadCategory(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        List<Category> categorise = categoryService.findAll();
        req.setAttribute("categorise", categorise);
    }
    protected void insert(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.setCharacterEncoding("UTF-8");
        resp.setCharacterEncoding("UTF-8");

        Product product = new Product();
        List<ImageProduct> images = new ArrayList<>();
        Store store = (Store) SessionUtil.getInstance().getValue(req, STORE_MODEL);

        product.setName(req.getParameter("name"));
        product.setCategoryId(Integer.valueOf(req.getParameter("categoryId")));
        product.setStoreId(store.getId());
        product.setPrice(Double.valueOf(req.getParameter("price")));
        product.setPromotionalPrice(Double.valueOf(req.getParameter("promotionalPrice")));
        product.setQuantity(Integer.valueOf(req.getParameter("quantity")));
        product.setDescription(req.getParameter("description"));

        // xử lý ảnh
        Collection<Part> parts = req.getParts();
        for(Part filePart : parts) {
            if(filePart.getHeader("content-disposition").contains("filename=")){
                String fileName = "" + System.currentTimeMillis();
                String realPath = UPLOAD_PRODUCT_DIRECTORY;
                if(filePart.getSize() != 0){
                    ImageProduct image = new ImageProduct();
                    image.setName(UploadUtil.processUpload(filePart.getName(), req, realPath, fileName));
                    images.add(image);
                }
            }
        }
        product.setImages(images);
        productService.insert(product);
    }
    protected void update(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.setCharacterEncoding("UTF-8");
        resp.setCharacterEncoding("UTF-8");

        Product product = new Product();
        List<ImageProduct> images = new ArrayList<>();

        product.setId(Integer.valueOf(req.getParameter("id")));
        product.setName(req.getParameter("name"));
        product.setCategoryId(Integer.valueOf(req.getParameter("categoryId")));
        product.setPrice(Double.valueOf(req.getParameter("price")));
        product.setPromotionalPrice(Double.valueOf(req.getParameter("promotionalPrice")));
        product.setQuantity(Integer.valueOf(req.getParameter("quantity")));
        product.setDescription(req.getParameter("description"));
        product.setStoreId(Integer.valueOf(req.getParameter("storeId")));

        // Image Product old
        List<ImageProduct> oldImage = imageProductService.findByProductId(product.getId());
        int flag = 0;
        Collection<Part> parts = req.getParts();
        for (Part filePart : parts) {
            if (filePart.getHeader("content-disposition").contains("filename=")) {
                String fileName = "" + System.currentTimeMillis();
                String realPath = UPLOAD_PRODUCT_DIRECTORY;
                ImageProduct image = new ImageProduct();
                if(filePart.getSize() == 0) {
                    image.setName(oldImage.get(flag).getName());
                    images.add(image);
                } else {
                    String fileNameImg = "";
                    if (oldImage.get(flag) != null) {
                        fileNameImg = oldImage.get(flag).getName();
                        DeleteImageUtil.processDelete(realPath, fileNameImg);
                    }
                    image.setName(UploadUtil.processUpload(filePart.getName(), req, realPath, fileName));
                    images.add(image);
                }
                flag++;
            }
        }
        product.setImages(images);
        productService.update(product);
    }
    protected void delete(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        String productId = req.getParameter("id");
        productService.delete(Integer.valueOf(productId));
        resp.sendRedirect(req.getContextPath() + "/vendor/product");
    }
}
