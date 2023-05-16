<%@ page language="java" contentType="text/html; charset=UTF-8"
         pageEncoding="UTF-8" %>
<%@include file="/common/taglib.jsp" %>
<div class="iq-top-navbar" style="background-image: linear-gradient(#0dd6b8, #85e79a); padding: 0 25px;">
    <div class="iq-navbar-custom">
        <nav class="navbar navbar-expand-lg navbar-light p-0">
            <div class="iq-menu-bt d-flex align-items-center">
                <div class="wrapper-menu">
                    <div class="main-circle"><i class="las la-bars"></i></div>
                </div>
                <div class="iq-navbar-logo d-flex justify-content-between">
                    <a href="#" class="header-logo">
                        <img src="<c:url value="/template/images/logo.png"/> " class="img-fluid rounded-normal" alt="">
                        <div class="logo-title">
                            <span class="text-primary text-uppercase">Booksto</span>
                        </div>
                    </a>
                </div>
            </div>
            <div class="navbar-breadcrumb">
                <h5 class="mb-0">Kênh người bán</h5>
            </div>
            <div class="collapse navbar-collapse" id="navbarSupportedContent">
                <ul class="navbar-nav ml-auto navbar-list" style="padding-top: 6px">
                    <li class="line-height">
                        <a href="#" class="search-toggle iq-waves-effect d-flex align-items-center">
                            <c:if test="${(sessionScope.USERMODEL.avatar == null) || (sessionScope.USERMODEL.avatar == '')}">
                                <img
                                        src="<c:url value='/template/images/default-avatar.png'/>"
                                        class="img-fluid rounded-circle mr-3" alt="user">
                            </c:if> <c:if test="${(sessionScope.USERMODEL.avatar != null) && (sessionScope.USERMODEL.avatar != '') }">
                            <c:url
                                    value="/image?fname=${sessionScope.USERMODEL.avatar}&type=user"
                                    var="imgAvatar"></c:url>
                            <img src="${imgAvatar}" class="img-fluid rounded-circle mr-3"
                                 alt="user">
                        </c:if>
                            <div class="caption" style="text-align: center">
                                <h6 class="mb-1 line-height">
                                    ${sessionScope.USERMODEL.firstname} ${sessionScope.USERMODEL.lastname}
                                </h6>
                                <span class="font-size-14 text-danger font-weight-bold">(${sessionScope.USERMODEL.eWallet}
                                    vnđ)</span>
                            </div>
                        </a>
                        <div class="iq-sub-dropdown iq-user-dropdown">
                            <div class="iq-card shadow-none m-0">
                                <div class="iq-card-body p-0">
                                    <a href="<c:url value="/web"/>" class="iq-sub-card iq-bg-primary-hover">
                                        <div class="media align-items-center">
                                            <div class="rounded iq-card-icon iq-bg-primary d-flex justify-content-center align-items-center">
                                                <i class="fa-solid fa-cart-shopping"></i>
                                            </div>
                                            <div class="media-body ml-3">
                                                <h6 class="mb-0 ">Mua hàng</h6>
                                            </div>
                                        </div>
                                    </a>
                                    <a href="<c:url value="/logout"/> " class="iq-sub-card iq-bg-primary-hover">
                                        <div class="media align-items-center">
                                            <div class="rounded iq-card-icon iq-bg-primary d-flex justify-content-center align-items-center">
                                                <i class="fa-solid fa-right-from-bracket"></i>
                                            </div>
                                            <div class="media-body ml-3">
                                                <h6 class="mb-0 ">Đăng xuất</h6>
                                            </div>
                                        </div>
                                    </a>
                                </div>
                            </div>
                        </div>
                    </li>
                </ul>
            </div>
        </nav>
    </div>
</div>