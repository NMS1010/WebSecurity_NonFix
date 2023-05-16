package com.mdk.dao;

import com.mdk.models.ReportOrder;

import java.util.List;

public interface IReportOrderDAO {
    List<ReportOrder> getReportOrder(int storeId, String status, String dateStart, String dateEnd);
}
