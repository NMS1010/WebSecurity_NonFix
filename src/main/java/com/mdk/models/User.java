package com.mdk.models;
import org.apache.poi.ss.usermodel.*;

import java.util.*;

public class User extends  AbstractModel<User>{

    private static CellStyle cellStyleFormatDouble = null;
    private String sex;
    private String firstname;
    private String lastname;
    private String id_card;
    private String email;
    private String phone;
    private boolean IsEmailActive;
    private boolean isPhoneActive;
    private String password;
    private String role;
    private String avatar;
    private Double eWallet;
    private int totalOrders;
    private String code;
    
    

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getSex() {
        return sex;
    }

    public void setSex(String sex) {
        this.sex = sex;
    }

    public void setTotalOrders(int totalOrders) {
        this.totalOrders = totalOrders;
    }

    public int getTotalOrders() {
        return totalOrders;
    }

    public String getFirstname() {
        return firstname;
    }

    public void setFirstname(String firstname) {
        this.firstname = firstname;
    }

    public String getLastname() {
        return lastname;
    }

    public void setLastname(String lastname) {
        this.lastname = lastname;
    }

    public String getId_card() {
        return id_card;
    }

    public void setId_card(String id_card) {
        this.id_card = id_card;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPhone() {
        return phone;
    }

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public boolean isIsEmailActive() {
        return IsEmailActive;
    }

    public void setIsEmailActive(boolean isEmailActive) {
        IsEmailActive = isEmailActive;
    }

    public boolean isPhoneActive() {
        return isPhoneActive;
    }

    public void setPhoneActive(boolean isPhoneActive) {
        this.isPhoneActive = isPhoneActive;
    }

    public String getRole() {
        return role;
    }

    public void setRole(String role) {
        this.role = role;
    }

    public String getAvatar() {
        return avatar;
    }

    public void setAvatar(String avatar) {
        this.avatar = avatar;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Double geteWallet() {
        return eWallet;
    }

    public void seteWallet(Double eWallet) {
        this.eWallet = eWallet;
    }

    public static List<HeaderElementExcel> getColumns() {
        List<HeaderElementExcel> list = new ArrayList<>();
        list.add(new HeaderElementExcel(0, "Họ"));
        list.add(new HeaderElementExcel(1, "Tên"));
        list.add(new HeaderElementExcel(2, "CMND/CCCD"));
        list.add(new HeaderElementExcel(3, "Email"));
        list.add(new HeaderElementExcel(4, "Số điện thoại"));
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
        cell.setCellValue(lastname);

        cell = row.createCell(1);
        cell.setCellValue(firstname);

        cell = row.createCell(2);
        cell.setCellValue(id_card);

        cell = row.createCell(3);
        cell.setCellValue(email);

        cell = row.createCell(4);
        cell.setCellValue(phone);
    }
}
