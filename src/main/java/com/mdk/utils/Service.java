package com.mdk.utils;

import com.mdk.models.HeaderElementExcel;
import org.apache.poi.ss.usermodel.*;

import java.util.List;

public class Service {
    public static void writeHeader(Sheet sheet, int rowIndex, List<HeaderElementExcel> list) {
        CellStyle cellStyle = ExportExcel.createStyleForHeader(sheet);
        Row row = sheet.createRow(rowIndex);

        Cell cell = row.createCell(list.get(0).getIndex());
        cell.setCellStyle(cellStyle);
        cell.setCellValue(list.get(0).getName());

        for (int i = 1; i< list.size(); i++) {
            cell = row.createCell(list.get(i).getIndex());
            cell.setCellStyle(cellStyle);
            cell.setCellValue(list.get(i).getName());
        }
    }

}
