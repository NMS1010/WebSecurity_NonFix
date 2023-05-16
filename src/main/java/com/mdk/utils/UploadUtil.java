package com.mdk.utils;

import static com.mdk.utils.AppConstant.UPLOAD_STORE_DIRECTORY;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.Part;

import org.apache.commons.io.FilenameUtils;

@MultipartConfig(fileSizeThreshold = 1024 * 1024 * 10, // 10MB
        maxFileSize = 1024 * 1024 * 50, // 50MB
        maxRequestSize = 1024 * 1024 * 50) // 50MB
public class UploadUtil {
    private static final long serialVersionUID = 1L;

    public static String processUpload(String fieldName, HttpServletRequest req, String storeFolder, String storeFilename) 
            throws IOException, ServletException {
        Part filePart = req.getPart(fieldName);
        if(filePart == null || filePart.getSize()==0) {
            return "";
        }

        if(storeFolder ==null) {
            storeFolder = UPLOAD_STORE_DIRECTORY;
        }
        if (storeFilename == null) {
            storeFilename = Paths.get(filePart.getSubmittedFileName()).getFileName().toString();
        }else {
            storeFilename+="." + FilenameUtils.getExtension(Paths.get(filePart.getSubmittedFileName()).getFileName().toString());
        }
        Path uploadPath = Paths.get(storeFolder);
        if(!Files.exists(uploadPath)) {
            Files.createDirectories(uploadPath);
        }
        filePart.write(Paths.get(uploadPath.toString(),storeFilename).toString());
        return storeFilename;
    }
}
