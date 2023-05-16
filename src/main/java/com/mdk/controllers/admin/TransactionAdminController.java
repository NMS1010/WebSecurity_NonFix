package com.mdk.controllers.admin;

import static com.mdk.utils.AppConstant.TOTAL_ITEM_IN_PAGE;

import java.io.IOException;
import java.util.Collections;
import java.util.Comparator;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.mdk.models.Store;
import com.mdk.models.Transaction;
import com.mdk.paging.PageRequest;
import com.mdk.paging.Pageble;
import com.mdk.services.IStoreService;
import com.mdk.services.ITransactionService;
import com.mdk.services.impl.StoreService;
import com.mdk.services.impl.TransactionService;
import com.mdk.utils.ExportExcel;

@WebServlet(urlPatterns = {"/admin/transaction"})
public class TransactionAdminController extends HttpServlet{

    private static final long serialVersionUID = 1L;
    ITransactionService transactionService = new TransactionService();
    IStoreService storeService = new StoreService();
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        transactionPage(req, resp);
        List<Transaction> reportTransaction = transactionService.findAllForReport();
        final String excelFilePath = "E:\\reportTransaction.xls";
        ExportExcel.writeExcel(reportTransaction, excelFilePath, Transaction.getColumns(), "reportTransaction");
        req.getRequestDispatcher("/views/admin/transaction/index.jsp").forward(req, resp);
    }
    protected void transactionPage(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        req.setCharacterEncoding("UTF-8");
        resp.setCharacterEncoding("UTF-8");
        int totalItemInPage = TOTAL_ITEM_IN_PAGE;
        String indexPage = req.getParameter("index");
        String keyword = req.getParameter("search");
        if(indexPage == null) {
            indexPage = "1";
        }

        List<Store> storesList = storeService.findAll();
        //Sort name
        Collections.sort(storesList, new Comparator<Store>() {
            @Override
            public int compare(Store o1, Store o2) {
                return o1.getName().compareTo(o2.getName());
            }
        });
        int storeId = req.getParameter("storeId") == null ? storesList.get(0).getId() : Integer.parseInt(req.getParameter("storeId"));
        //

        int countP = transactionService.count(storeId, keyword);
        int endP = (countP/totalItemInPage);
        if (countP % totalItemInPage != 0) {
            endP ++;
        }

        Pageble pageble = new PageRequest(Integer.parseInt(indexPage), totalItemInPage, null);
        List<Transaction> transactionList = transactionService.findAll(pageble, storeId, keyword);
        req.setAttribute("storeId", storeId);
        req.setAttribute("storesList", storesList);
        req.setAttribute("countP", countP);
        req.setAttribute("totalItemInPage", totalItemInPage);
        req.setAttribute("endP", endP);
        req.setAttribute("tag", indexPage);
        req.setAttribute("transactionList", transactionList);
        req.setAttribute("search", keyword);
    }
}