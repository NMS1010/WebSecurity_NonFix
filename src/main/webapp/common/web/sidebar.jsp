<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@include file="/common/taglib.jsp"%>

<div class="iq-sidebar">
	<div class="iq-sidebar-logo d-flex justify-content-between">
		<a href="#" class="header-logo"> <img
			src="<c:url value ='/template/images/logo.png'/>"
			class="img-fluid rounded-normal" alt="">
			<div class="logo-title">
				<span class="text-primary text-uppercase">MDK Shop</span>
			</div>
		</a>
	</div>
	<div id="sidebar-scrollbar">
		<nav class="iq-sidebar-menu">
			<ul id="iq-sidebar-toggle" class="iq-menu">

				<li id="home" class=""><a href="<c:url value="/web" />"><i
						class="fa fa-home"></i>Trang chủ</a></li>
				<li id="book"><a href="<c:url value="/web/book/search" />"><i
						class="ri-book-2-fill"></i>Sản phẩm</a></li>
				<li id="store"><a href="<c:url value="/web/store/search" />"><i
						class="ri-store-2-fill"></i>Cửa hàng</a></li>
				<li id="user"><a href="<c:url value="/web/user/search" />"><i
						class="ri-user-2-line"></i>Người dùng</a></li>
				<li><a href="./book-pdf.html"><i class="ri-account-box-fill"></i>Tài
						khoản</a></li>
				<li><a href="./Checkout.html"><i
						class="ri-checkbox-multiple-blank-line"></i>Thanh toán</a></li>
				<li><a href="./wishlist.html"><i class="ri-heart-line"></i>Yêu
						thích</a></li>
			</ul>
		</nav>
	</div>
</div>
<script>
	function changeActive() {
		var url = window.location.pathname;
		if (url.includes("book")) {
			document.getElementById("book").classList.add("active");
		} else if (url.includes("store")) {
			document.getElementById("store").classList.add("active");
		} else {
			document.getElementById("home").classList.add("active");
		}
	}
	
	window.onload = function(){
		changeActive()
	};
</script>