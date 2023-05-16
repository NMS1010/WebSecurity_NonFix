<%@ page language="java" contentType="text/html; charset=UTF-8"
         pageEncoding="UTF-8" %>
<div class="iq-sidebar">
  <div class="iq-sidebar-logo d-flex justify-content-between">
    <a href="admin/user/all" class="header-logo">
      <img src="<c:url value="/template/images/logo.png"/>" class="img-fluid rounded-normal" alt="">
      <div class="logo-title">
        <span class="text-primary text-uppercase">MDK</span>
      </div>
    </a>
  </div>
  <div id="sidebar-scrollbar">
    <nav class="iq-sidebar-menu">
      <ul id="iq-sidebar-toggle" class="iq-menu">
        <li>
          <a href="#user" class="iq-waves-effect" data-toggle="collapse" aria-expanded="false"><span
                  class="ripple rippleEffect"></span><i class="fa-solid fa-user"></i></i><span>Người dùng</span><i
                  class="fa-solid fa-chevron-right iq-arrow-right"></i></a>
          <ul id="user" class="iq-submenu collapse" data-parent="#iq-sidebar-toggle">
            <li><a href="<c:url value='/admin/user/all'/>">Tất cả</a></li>
            <li><a href="<c:url value='/admin/user/closest'/>">Người dùng mới</a></li>
          </ul>
        </li>
        <li>
          <a href="#store" class="iq-waves-effect" data-toggle="collapse" aria-expanded="false"><span
                  class="ripple rippleEffect"></span><i class="fa-solid fa-store"></i></i><span>Cửa hàng</span><i
                  class="fa-solid fa-chevron-right iq-arrow-right"></i></a>
          <ul id="store" class="iq-submenu collapse" data-parent="#iq-sidebar-toggle">
            <li><a href="<c:url value='/admin/store/all'/>"></i>Tất cả cửa hàng</a></li>
            <li><a href="<c:url value='/admin/store/statistic'/>"></i>Thống kê</a></li>
          </ul>
        </li>
        <li>
          <a href="#product" class="iq-waves-effect" data-toggle="collapse" aria-expanded="false"><span
                  class="ripple rippleEffect"></span><i class="fa-brands fa-product-hunt"></i><span>Sản phẩm</span><i
                  class="fa-solid fa-chevron-right iq-arrow-right"></i></a>
          <ul id="product" class="iq-submenu collapse" data-parent="#iq-sidebar-toggle">
            <li><a href="<c:url value='/admin/product/category'/>">Thể loại</a></li>
            <li><a href="<c:url value='/admin/product/permit'/>">Sản phẩm được cho phép</a></li>
            <li><a href="<c:url value='/admin/product/prohibit'/>">Sản phẩm bị cấm</a></li>
          </ul>
        </li>
        <li>
          <a href="#order" class="iq-waves-effect" data-toggle="collapse" aria-expanded="false"><span
                  class="ripple rippleEffect"></span><i class="fa-solid fa-file-lines"></i><span>Đơn hàng</span><i
                  class="fa-solid fa-chevron-right iq-arrow-right"></i></a>
          <ul id="order" class="iq-submenu collapse" data-parent="#iq-sidebar-toggle">
            <li><a href="<c:url value='/admin/order?state=delivered'/>">Đơn hàng đã giao</a></li>
            <li><a href="<c:url value='/admin/order?state=shipped'/>">Đơn hàng đang vận chuyển</a>
            </li>
          </ul>
        </li>
        <li><a href="<c:url value='/admin/delivery'/>"><i class="fa-solid fa-truck"></i>Đơn vị vận chuyển</a></li>
        <li><a href="<c:url value='/admin/transaction'/>"><i class="fa-solid fa-file-lines"></i>Giao dịch</a></li>
        <li><a href="<c:url value='/logout'/>" class="text-danger"><i class="fa-solid fa-right-from-bracket"></i>Đăng xuất</a></li>
      </ul>
    </nav>
  </div>
</div>