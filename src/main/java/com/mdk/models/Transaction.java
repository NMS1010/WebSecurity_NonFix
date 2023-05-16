package com.mdk.models;


import org.apache.poi.ss.usermodel.*;

import java.util.ArrayList;
import java.util.List;

public class Transaction extends AbstractModel<Transaction>{
    private static CellStyle cellStyleFormatDouble = null;
    private int userId ;
    private String nameUser;
    private String nameStore;
    private int storeId;
    private boolean isUp   ;
    private Double amount ;
    private String isUpString;

    public String getNameStore() {
        return nameStore;
    }

    public void setNameStore(String nameStore) {
        this.nameStore = nameStore;
    }

    public boolean isUp() {
        return isUp;
    }

    public String getIsUpString() {
        return isUpString;
    }

    public String getNameUser() {
        return nameUser;
    }

    public void setNameUser(String nameUser) {
        this.nameUser = nameUser;
    }

    public void setIsUpString(String isUpString) {
        this.isUpString = isUpString;
    }

    public int getUserId() {
        return userId;
    }

    public void setUserId(int userId) {
        this.userId = userId;
    }

    public int getStoreId() {
        return storeId;
    }

    public void setStoreId(int storeId) {
        this.storeId = storeId;
    }

    public boolean getUp() {
        return isUp;
    }

    public void setUp(boolean up) {
        isUp = up;
    }

    public Double getAmount() {
        return amount;
    }

    public void setAmount(Double amount) {
        this.amount = amount;
    }

    public static List<HeaderElementExcel> getColumns() {
        List<HeaderElementExcel> list = new ArrayList<>();
        list.add(new HeaderElementExcel(0, "Tên người dùng"));
        list.add(new HeaderElementExcel(1, "Tên cửa hàng"));
        list.add(new HeaderElementExcel(2, "Số tiền"));
        list.add(new HeaderElementExcel(3, "Nội dung"));
        list.add(new HeaderElementExcel(4, "Thời gian"));
        return list;
    }

    @Override
    public void writeReport(Row row) {
        if (cellStyleFormatDouble == null) {
            Workbook workbook = row.getSheet().getWorkbook();
            DataFormat format = workbook.createDataFormat();
            cellStyleFormatDouble = workbook.createCellStyle();
            cellStyleFormatDouble.setDataFormat(format.getFormat("#,##0.00"));
        }

        Cell cell = row.createCell(0);
        cell.setCellValue(nameUser);

        cell = row.createCell(1);
        cell.setCellValue(nameStore);

        cell = row.createCell(2);
        cell.setCellValue(amount);

        cell = row.createCell(3);
        cell.setCellValue(isUpString);

        cell = row.createCell(4);
        cell.setCellValue(getCreatedAt().toString());

    }
}
