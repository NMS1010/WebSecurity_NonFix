package com.mdk.models;

public class HeaderElementExcel {
    private int index;
    private String name;

    public int getIndex() {
        return index;
    }

    public void setIndex(int index) {
        this.index = index;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public HeaderElementExcel() {

    }
    public HeaderElementExcel(int index, String name) {
        this.index = index;
        this.name = name;
    }
}
