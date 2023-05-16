package com.mdk.utils;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;

public class DeleteImageUtil {
    public static void processDelete(String storeFolder, String storeFilename) {
        File file = new File(storeFolder +"\\" + storeFilename);
        try {
            Files.delete(Paths.get(file.getPath()));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
