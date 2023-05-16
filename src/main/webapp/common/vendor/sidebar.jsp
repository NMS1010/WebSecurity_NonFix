<%@ page language="java" contentType="text/html; charset=UTF-8"
         pageEncoding="UTF-8" %>
<%@include file="/common/taglib.jsp" %>
<div class="iq-sidebar">
    <div class="iq-sidebar-logo">
        <a href="#" class="header-logo">
            <img src="<c:url value="/template/images/logo.png"/> " class="img-fluid rounded-normal" alt="">
            <div class="logo-title">
                <span class="text-primary text-uppercase">MDK Shop</span>
            </div>
        </a>
        <div class="logo-title" style="margin-top: 5px">
            <span style="margin-right: 5px">Số dư Ví:</span>
            <span class="text-danger text-uppercase">
                ${sessionScope.STORE.eWallet} vnđ
            </span>
        </div>
    </div>
    <div id="sidebar-scrollbar">
        <nav class="iq-sidebar-menu">
            <ul id="iq-sidebar-toggle" class="iq-menu">
                <li id="home" class="">
                    <a aria-expanded="false" href="<c:url value="/vendor/home" />">
                        <i class="fa-solid fa-book-open"></i>
                        Trang chủ
                    </a>
                </li>
                <li id="store" class="">
                    <a aria-expanded="false" href="<c:url value="/vendor/store" />">
                        <i class="fa-solid fa-store"></i>
                        Thông tin cửa hàng
                    </a>
                </li>
                <li id="product" class="">
                    <a aria-expanded="false"
                       href="<c:url value="/vendor/product/category?categoryId=0"/> ">
                        <i class="fa-solid fa-table-list"></i>
                        Quản lý sản phẩm
                    </a>
                </li>
                <li id="order" class="">
                    <a aria-expanded="false" href="<c:url value="/vendor/order/manager?status=all"/>">
                        <i class="fa-solid fa-truck-fast"></i>
                        Quản lý đơn hàng
                    </a>
                </li>
                <li id="transaction" class="">
                    <a aria-expanded="false" href="<c:url value="/vendor/transaction"/>">
                        <i class="fa-solid fa-coins"></i>
                        Quản lý giao dịch
                    </a>
                </li>
                <li id="review" class="">
                    <a aria-expanded="false" href="<c:url value="/vendor/review"/>">
                        <i class="fa-solid fa-glasses"></i>
                        Đánh giá cửa hàng
                    </a>
                </li>
                <li id="statistic" class="">
                    <a aria-expanded="false" href="<c:url value="/vendor/statistic"/>">
                        <i class="fa-solid fa-chart-simple"></i>
                        Thống kê
                    </a>
                </li>
                
                <li id="guide" class="">
                    <a aria-expanded="false" href="<c:url value="/vendor/download-guide"/>">
                        <i class="fa-solid fa-download"></i>
                        Hướng dẫn
                    </a>
                </li>
            </ul>
        </nav>
    </div>
</div>
<script type="text/javascript">
    function changeActive() {
        const url = window.location.pathname;
        if (url.includes("store")) {
            document.getElementById("store").classList.add("active");
        } else if (url.includes("product")) {
            document.getElementById("product").classList.add("active");
        } else if (url.includes("order")) {
            document.getElementById("order").classList.add("active");
        } else if (url.includes("home")) {
            document.getElementById("home").classList.add("active");
        } else if (url.includes("transaction")) {
            document.getElementById("transaction").classList.add("active");
        } else if (url.includes("statistic")){
            document.getElementById("statistic").classList.add("active");
        } else if (url.includes("review")){
            document.getElementById("review").classList.add("active");
        }
    }

    window.onload = function () {
        changeActive();
    }
</script>