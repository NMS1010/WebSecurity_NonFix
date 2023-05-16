package com.mdk.services.impl;

import com.mdk.dao.IReportOrderDAO;
import com.mdk.dao.impl.ReportOrderDAO;
import com.mdk.models.ReportOrder;
import com.mdk.services.IReportOrderService;

import java.util.List;

public class ReportOrderService implements IReportOrderService {
    IReportOrderDAO reportOrderDAO = new ReportOrderDAO();
    @Override
    public List<ReportOrder> getReportOrder(int storeId, String status, String dateStart, String dateEnd) {
        return reportOrderDAO.getReportOrder(storeId, status, dateStart, dateEnd);
    }
}
