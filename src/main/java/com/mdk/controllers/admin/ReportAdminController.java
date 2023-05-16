package com.mdk.controllers.admin;
import static com.mdk.utils.AppConstant.EXPORT_REPORT;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.poi.hssf.usermodel.HSSFWorkbook;
import org.apache.poi.ss.usermodel.BorderStyle;
import org.apache.poi.ss.usermodel.Cell;
import org.apache.poi.ss.usermodel.CellStyle;
import org.apache.poi.ss.usermodel.DataFormat;
import org.apache.poi.ss.usermodel.FillPatternType;
import org.apache.poi.ss.usermodel.Font;
import org.apache.poi.ss.usermodel.IndexedColors;
import org.apache.poi.ss.usermodel.Row;
import org.apache.poi.ss.usermodel.Sheet;
import org.apache.poi.ss.usermodel.Workbook;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import com.mdk.models.User;
import com.mdk.services.IUserService;
import com.mdk.services.impl.UserService;
//@WebServlet(urlPatterns = "/admin/user/all")
public class ReportAdminController extends HttpServlet {
    private static final long serialVersionUID = 1L;
    public static final int COLUMN_LASTNAME = 0;
    public static final int COLUMN_FIRSTNAME = 1;
    public static final int COLUMN_CARD_ID = 2;
    public static final int COLUMN_EMAIL = 3;
    public static final int COLUMN_PHONE = 4;

    private static CellStyle cellStyleFormatDouble = null;
    IUserService userService = new UserService();

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        resp.setContentType("text/html");
        List<User> reportUser = userService.findAllForReport();
        final String excelFilePath = EXPORT_REPORT;
        writeExcel(reportUser, excelFilePath);
    }

    public static void writeExcel(List<User> reportUser, String excelFilePath) throws IOException {
        Workbook workbook = getWorkbook(excelFilePath);
        Sheet sheet = workbook.createSheet("reportUser");
        int rowIndex = 0;
        writeHeader(sheet, rowIndex);
        rowIndex++;
        for (User item : reportUser) {
            Row row = sheet.createRow(rowIndex);
            writeReport(item, row);
            rowIndex++;
        }
        int numberOfColumn = sheet.getRow(0).getPhysicalNumberOfCells();
        autosizeColumn(sheet, numberOfColumn);

        createOutputFile(workbook, excelFilePath);
        System.out.println("Done!!!");
    }

    public static Workbook getWorkbook(String excelFilePath) throws  IOException {
        Workbook workbook = null;
        File file = new File(excelFilePath);
        if (!file.exists()) {
            FileOutputStream fileOut = new FileOutputStream(excelFilePath);
            fileOut.close();
        }
        if (excelFilePath.endsWith("xlsx")) {
            workbook = new XSSFWorkbook();
        } else if (excelFilePath.endsWith("xls")) {
            workbook = new HSSFWorkbook();
        } else {
            throw new IllegalArgumentException("The specified file is not Excel file");
        }
        return  workbook;
    }
    private  static  void writeHeader(Sheet sheet, int rowIndex) {
        CellStyle cellStyle = createStyleForHeader(sheet);
        Row row = sheet.createRow(rowIndex);

        Cell cell = row.createCell(COLUMN_LASTNAME);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Họ");

        cell = row.createCell(COLUMN_FIRSTNAME);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Tên");

        cell = row.createCell(COLUMN_CARD_ID);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("CMND/CCCD");

        cell = row.createCell(COLUMN_EMAIL);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Email");

        cell = row.createCell(COLUMN_PHONE);
        cell.setCellStyle(cellStyle);
        cell.setCellValue("Số điện thoại");

    }
    private static void writeReport(User reportUser, Row row) {
        if (cellStyleFormatDouble == null) {
            Workbook workbook = row.getSheet().getWorkbook();
            DataFormat format = workbook.createDataFormat();
            cellStyleFormatDouble = workbook.createCellStyle();
            cellStyleFormatDouble.setDataFormat(format.getFormat("#,##0.00"));
        }
        Cell cell = row.createCell(COLUMN_LASTNAME);
        cell.setCellValue(reportUser.getLastname());

        cell = row.createCell(COLUMN_FIRSTNAME);
        cell.setCellValue(reportUser.getFirstname());

        cell = row.createCell(COLUMN_CARD_ID);
        cell.setCellValue(reportUser.getId_card());

        cell = row.createCell(COLUMN_EMAIL);
        cell.setCellValue(reportUser.getEmail());

        cell = row.createCell(COLUMN_PHONE);
        cell.setCellValue(reportUser.getPhone());
    }

    private static CellStyle createStyleForHeader(Sheet sheet) {
        Font font = sheet.getWorkbook().createFont();
        font.setFontName("Times New Roman");
        font.setBold(true);
        font.setFontHeightInPoints((short) 14); // font size
        font.setColor(IndexedColors.BLACK.getIndex()); // text color

        // Create CellStyle
        CellStyle cellStyle = sheet.getWorkbook().createCellStyle();
        cellStyle.setFont(font);
        cellStyle.setFillForegroundColor(IndexedColors.YELLOW.getIndex());
        cellStyle.setFillPattern(FillPatternType.SOLID_FOREGROUND);
        cellStyle.setBorderBottom(BorderStyle.THIN);
        return cellStyle;
    }
    private static void autosizeColumn(Sheet sheet, int lastColumn) {
        for (int columnIndex = 0; columnIndex < lastColumn; columnIndex++) {
            sheet.autoSizeColumn(columnIndex);
        }
    }
    private static void createOutputFile(Workbook workbook, String excelFilePath) throws IOException {
        try (OutputStream os = new FileOutputStream(excelFilePath)) {
            workbook.write(os);
        }
    }
}
