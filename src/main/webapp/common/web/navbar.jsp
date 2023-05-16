<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@include file="/common/taglib.jsp"%>

<div class="iq-top-navbar"
	style="width: 100%; padding: 0 100px; background-image: linear-gradient(#0dd6b8, #85e79a)">
	<div class="iq-navbar-custom">
		<nav class="navbar navbar-expand-lg navbar-light p-0">
			<div class="iq-menu-bt d-flex align-items-center">
				<div class="wrapper-menu">
					<div class="main-circle">
						<i class="las la-bars"></i>
					</div>
				</div>
				<div class="iq-navbar-logo d-flex justify-content-between">
					<c:if test="${not empty sessionScope.USER_MODEL}">
						<a href="<c:url value='/web'/>" class="header-logo"> <img
							src="../template/images/logo.png"
							class="img-fluid rounded-normal" alt="">
							<div class="logo-title">
								<span class="text-primary text-uppercase">MDK Book</span>
							</div>
						</a>
					</c:if>
					<c:if test="${empty sessionScope.USER_MODEL}">
						<a href="<c:url value='/home'/>" class="header-logo"> <img
							src="../template/images/logo.png"
							class="img-fluid rounded-normal" alt="">
							<div class="logo-title">
								<span class="text-primary text-uppercase">MDK Book</span>
							</div>
						</a>
					</c:if>
				</div>
			</div>
			<div class="navbar-breadcrumb ">
				<div class="iq-navbar-logo d-flex justify-content-between">
					<c:if test="${not empty sessionScope.USER_MODEL}">
						<a href="<c:url value='/web'/>" class="header-logo"> <img
							src="<c:url value="/template/images/logo.png"/>"
							class="img-fluid rounded-normal" alt="">
							<div class="logo-title">
								<h2 class="text-primary text-uppercase text-white"
									style="font-size: 28px !important; margin-left: 5px; line-height: 45px;">MDK
									SHOP</h2>
							</div>
						</a>
					</c:if>
					<c:if test="${empty sessionScope.USER_MODEL}">
						<a href="<c:url value='/home'/>" class="header-logo"> <img
							src="<c:url value="/template/images/logo.png"/>"
							class="img-fluid rounded-normal" alt="">
							<div class="logo-title">
								<h2 class="text-primary text-uppercase text-white"
									style="font-size: 28px !important; margin-left: 5px; line-height: 45px;">MDK
									SHOP</h2>
							</div>
						</a>
					</c:if>

				</div>

				<%-- <h2 class="mb-0 text-white" style="font-size: 28px !important;"><a href="<c:url value='/web'/>" class="header-logo">MDK
					SHOP</a></h2> --%>

			</div>
			<div class="iq-search-bar d-flex align-items-center">
				<form method="post" class="searchbox d-flex mt-3">
					<input id="searchinput" name="searchkeyword" type="text"
						oninput="changeFormAction()" class="text search-input"
						placeholder="Tìm kiếm sách..." value="${searchkeyword}"> <a
						class="search-link" href="#"><i class="ri-search-line"></i></a>
					<c:if test="${not empty sessionScope.USER_MODEL}">
						<button id="searchbutton"
							formaction="<c:url value='/web/book/search?category=0&store=0&rating=-1&minPrice=0&maxPrice=1000000&search=${searchkeyword}'/>"
							class="btn text-primary search-data ml-2"
							style="background-color: white">
							<i class="ri-search-line"></i>
						</button>
					</c:if>
					<c:if test="${empty sessionScope.USER_MODEL}">
						<button id="searchbutton"
							formaction="<c:url value='/home/book/search?category=0&store=0&rating=-1&minPrice=0&maxPrice=1000000&search=${searchkeyword}'/>"
							class="btn text-primary search-data ml-2"
							style="background-color: white">
							<i class="ri-search-line"></i>
						</button>
					</c:if>

				</form>
				<div>
					<c:if test="${not empty sessionScope.USER_MODEL}">
						<a href="<c:url value="/web/store/search"/>"
							class="btn text-primary search-data ml-2"
							style="background-color: white; height: 40px"> Trang tìm kiếm
							cửa hàng</a>
					</c:if>
					<c:if test="${empty sessionScope.USER_MODEL}">
						<a href="<c:url value="/home/store/search"/>"
							class="btn text-primary search-data ml-2"
							style="background-color: white; height: 40px"> Trang tìm kiếm
							cửa hàng</a>
					</c:if>

				</div>
			</div>

			<button class="navbar-toggler" type="button" data-toggle="collapse"
				data-target="#navbarSupportedContent"
				aria-controls="navbarSupportedContent"
				aria-label="Toggle navigation">
				<i class="ri-menu-3-line"></i>
			</button>
			<div class="collapse navbar-collapse" id="navbarSupportedContent">
				<ul class="navbar-nav ml-auto navbar-list">
					<li class="nav-item nav-icon search-content"><a href="#"
						class="search-toggle iq-waves-effect text-gray rounded"> <i
							class="ri-search-line"></i>
					</a>
						<form action="#" class="search-box p-0">
							<input type="text" class="text search-input"
								placeholder="Type here to search..."> <a
								class="search-link" href="#"><i class="ri-search-line"></i></a>
						</form></li>
					<li class="nav-item nav-icon"><a href="#"
						class="search-toggle iq-waves-effect text-gray rounded"> <i
							class="ri-notification-2-line text-white"></i> <span
							class="bg-primary dots"></span>
					</a>
						<div class="iq-sub-dropdown">
							<div class="iq-card shadow-none m-0">
								<div class="iq-card-body p-0">
									<div class="bg-primary p-3">
										<h5 class="mb-0 text-white">
											All Notifications<small
												class="badge  badge-light float-right pt-1">4</small>
										</h5>
									</div>
									<a href="#" class="iq-sub-card">
										<div class="media align-items-center">
											<div class="">
												<img class="avatar-40 rounded" src="images/user/01.jpg"
													alt="">
											</div>
											<div class="media-body ml-3">
												<h6 class="mb-0 ">Emma Watson Barry</h6>
												<small class="float-right font-size-12">Just Now</small>
												<p class="mb-0">95 MB</p>
											</div>
										</div>
									</a> <a href="#" class="iq-sub-card">
										<div class="media align-items-center">
											<div class="">
												<img class="avatar-40 rounded" src="images/user/02.jpg"
													alt="">
											</div>
											<div class="media-body ml-3">
												<h6 class="mb-0 ">New customer is join</h6>
												<small class="float-right font-size-12">5 days ago</small>
												<p class="mb-0">Cyst Barry</p>
											</div>
										</div>
									</a> <a href="#" class="iq-sub-card">
										<div class="media align-items-center">
											<div class="">
												<img class="avatar-40 rounded" src="images/user/03.jpg"
													alt="">
											</div>
											<div class="media-body ml-3">
												<h6 class="mb-0 ">Two customer is left</h6>
												<small class="float-right font-size-12">2 days ago</small>
												<p class="mb-0">Cyst Barry</p>
											</div>
										</div>
									</a> <a href="#" class="iq-sub-card">
										<div class="media align-items-center">
											<div class="">
												<img class="avatar-40 rounded" src="images/user/04.jpg"
													alt="">
											</div>
											<div class="media-body ml-3">
												<h6 class="mb-0 ">New Mail from Fenny</h6>
												<small class="float-right font-size-12">3 days ago</small>
												<p class="mb-0">Cyst Barry</p>
											</div>
										</div>
									</a>
								</div>
							</div>
						</div></li>
					<li class="nav-item nav-icon dropdown"><a href="#"
						class="search-toggle iq-waves-effect text-gray rounded"> <i
							class="ri-shopping-cart-2-line text-white"></i> <span
							class="badge badge-danger count-cart rounded-circle">${sessionScope.COUNT_CART_HEADER}</span>
					</a>
						<div class="iq-sub-dropdown">
							<div class="iq-card shadow-none m-0">
								<div class="iq-card-body p-0 toggle-cart-info">
									<div class="bg-primary p-3">
										<h5 class="mb-0 text-white">
											Giỏ hàng<small class="badge  badge-light float-right pt-1">${sessionScope.COUNT_CART_HEADER}</small>
										</h5>
									</div>
									<c:forEach items="${sessionScope.CART_HEADER}" var="cart">
										<c:forEach items="${cart.cartItems}" var="cartItem">
											<form method="post">
												<a
													href="<c:url value="/web/book/detail?id=${cartItem.product.id}"/>"
													class="iq-sub-card">
													<div class="media align-items-center">
														<div class="">
															<c:url
																value="/image?fname=${cartItem.product.getImages().get(0).getName()}&type=product"
																var="imgUrl"></c:url>
															<img class="rounded" src="${imgUrl}" alt="">
														</div>
														<div class="media-body ml-3">
															<h6 class="mb-0 ">${cartItem.product.name}-
																x${cartItem.count}</h6>
															<p class="mb-0">${cartItem.count*cartItem.product.promotionalPrice}</p>
														</div>
														<div class="float-right font-size-24 text-danger">
															<button
																style="border: none; background-color: transparent"
																formaction="<c:url value="/web/cart/item/delete?id=${cartItem.id}"/>">
																<i class="ri-close-fill"></i>
															</button>
														</div>
													</div>
												</a>
											</form>
										</c:forEach>
									</c:forEach>
									<div class="d-flex align-items-center text-center p-3">
										<a class="btn btn-primary mr-2 iq-sign-btn"
											href="<c:url value="/web/cart"/>" role="button">Xem giỏ
											hàng</a> <a class="btn btn-primary iq-sign-btn"
											href="<c:url value="/web/book/search"/>" role="button">Shopping
											ngay</a>
									</div>
								</div>
							</div>
						</div></li>
					<li class="line-height pt-3 text-center"><c:choose>
							<c:when test="${not empty sessionScope.USERMODEL}">
								<a href="#"
									class="search-toggle iq-waves-effect d-flex align-items-center">
									<c:if
										test="${(sessionScope.USERMODEL.avatar == null) || (sessionScope.USERMODEL.avatar == '')}">
										<img
											src="<c:url value='/template/images/default-avatar.png'/>"
											class="img-fluid rounded-circle mr-3" alt="user">
									</c:if> <c:if
										test="${(sessionScope.USERMODEL.avatar != null) && (sessionScope.USERMODEL.avatar != '') }">
										<c:url
											value="/image?fname=${sessionScope.USERMODEL.avatar}&type=user"
											var="imgAvatar"></c:url>
										<img src="${imgAvatar}" class="img-fluid rounded-circle mr-3"
											alt="user">
									</c:if>
									<div class="caption" style="text-align: center">
										<h6 class="mb-1 line-height text-white">${sessionScope.USERMODEL.firstname}
											${sessionScope.USERMODEL.lastname}</h6>
										<span class="font-size-14 text-danger font-weight-bold">(${sessionScope.USERMODEL.eWallet}
											vnđ)</span>
									</div>
								</a>
								<div class="iq-sub-dropdown iq-user-dropdown">
									<div class="iq-card shadow-none m-0">
										<div class="iq-card-body p-0 ">
											<div class="bg-primary p-3">
												<h5 class="mb-0 text-white line-height">Hello
													${sessionScope.USERMODEL.firstname}
													${sessionScope.USERMODEL.lastname}</h5>
												<span class="text-white font-size-12">Đang hoạt động</span>
											</div>
											<a href="<c:url value="/web/user/edit"/>"
												class="iq-sub-card iq-bg-primary-hover">
												<div class="media align-items-center">
													<div class="rounded iq-card-icon iq-bg-primary">
														<i class="ri-file-user-line"></i>
													</div>
													<div class="media-body ml-3">
														<h6 class="mb-0 ">Tài khoản của tôi</h6>
													</div>
												</div>
											</a> <a href="<c:url value='/vendor/home'/>"
												class="iq-sub-card iq-bg-primary-hover">
												<div class="media align-items-center">
													<div class="rounded iq-card-icon iq-bg-primary">
														<i class="ri-lock-line"></i>
													</div>
													<div class="media-body ml-3">
														<h6 class="mb-0 ">Cửa hàng của tôi</h6>
													</div>
												</div>
											</a><a href="<c:url value='/web/order/list'/>"
												class="iq-sub-card iq-bg-primary-hover">
												<div class="media align-items-center">
													<div class="rounded iq-card-icon iq-bg-primary">
														<i class="ri-profile-line"></i>
													</div>
													<div class="media-body ml-3">
														<h6 class="mb-0 ">Đơn mua</h6>
													</div>
												</div>
											</a> <a href="<c:url value='/web/following'/>"
												class="iq-sub-card iq-bg-primary-hover">
												<div class="media align-items-center">
													<div class="rounded iq-card-icon iq-bg-primary">
														<i class="ri-account-box-line"></i>
													</div>
													<div class="media-body ml-3">
														<h6 class="mb-0 ">Sản phẩm yêu thích</h6>
													</div>
												</div>
											</a>
											<div class="d-inline-block w-100 text-center p-3">
												<a class="bg-primary iq-sign-btn"
													href="<c:url value="/logout"/>" role="button">Đăng xuất<i
													class="ri-login-box-line ml-2"></i></a>
											</div>
										</div>
									</div>
								</div>
							</c:when>

							<c:otherwise>
								<div class="iq-waves-effect d-flex align-items-center h-100"
									style="width: 160px; transform: translateY(-5px)">
									<a href="<c:url value="/login"/>"
										class="w-50 d-block text-white font-weight-bold">Đăng nhập</a>
									<a href="<c:url value="signup"/>"
										class="w-50 d-block text-white font-weight-bold">Đăng ký</a>
								</div>

							</c:otherwise>
						</c:choose></li>
					<%--            <li class="line-height pt-3">--%>
					<%--              <a href="#" class="search-toggle iq-waves-effect d-flex align-items-center">--%>
					<%--                <img src="images/user/1.jpg" class="img-fluid rounded-circle mr-3" alt="user">--%>
					<%--                <div class="caption">--%>
					<%--                  <h6 class="mb-1 line-height">Barry Tech</h6>--%>
					<%--                  <p class="mb-0 text-primary">$20.32</p>--%>
					<%--                </div>--%>
					<%--              </a>--%>
					<%--              <div class="iq-sub-dropdown iq-user-dropdown">--%>
					<%--                <div class="iq-card shadow-none m-0">--%>
					<%--                  <div class="iq-card-body p-0 ">--%>
					<%--                    <div class="bg-primary p-3">--%>
					<%--                      <h5 class="mb-0 text-white line-height">Hello Barry Tech</h5>--%>
					<%--                      <span class="text-white font-size-12">Available</span>--%>
					<%--                    </div>--%>
					<%--                    <a href="profile.html" class="iq-sub-card iq-bg-primary-hover">--%>
					<%--                      <div class="media align-items-center">--%>
					<%--                        <div class="rounded iq-card-icon iq-bg-primary">--%>
					<%--                          <i class="ri-file-user-line"></i>--%>
					<%--                        </div>--%>
					<%--                        <div class="media-body ml-3">--%>
					<%--                          <h6 class="mb-0 ">My Profile</h6>--%>
					<%--                          <p class="mb-0 font-size-12">View personal profile details.</p>--%>
					<%--                        </div>--%>
					<%--                      </div>--%>
					<%--                    </a>--%>
					<%--                    <a href="profile-edit.html" class="iq-sub-card iq-bg-primary-hover">--%>
					<%--                      <div class="media align-items-center">--%>
					<%--                        <div class="rounded iq-card-icon iq-bg-primary">--%>
					<%--                          <i class="ri-profile-line"></i>--%>
					<%--                        </div>--%>
					<%--                        <div class="media-body ml-3">--%>
					<%--                          <h6 class="mb-0 ">Edit Profile</h6>--%>
					<%--                          <p class="mb-0 font-size-12">Modify your personal details.</p>--%>
					<%--                        </div>--%>
					<%--                      </div>--%>
					<%--                    </a>--%>
					<%--                    <a href="account-setting.html" class="iq-sub-card iq-bg-primary-hover">--%>
					<%--                      <div class="media align-items-center">--%>
					<%--                        <div class="rounded iq-card-icon iq-bg-primary">--%>
					<%--                          <i class="ri-account-box-line"></i>--%>
					<%--                        </div>--%>
					<%--                        <div class="media-body ml-3">--%>
					<%--                          <h6 class="mb-0 ">Account settings</h6>--%>
					<%--                          <p class="mb-0 font-size-12">Manage your account parameters.</p>--%>
					<%--                        </div>--%>
					<%--                      </div>--%>
					<%--                    </a>--%>
					<%--                    <a href="privacy-setting.html" class="iq-sub-card iq-bg-primary-hover">--%>
					<%--                      <div class="media align-items-center">--%>
					<%--                        <div class="rounded iq-card-icon iq-bg-primary">--%>
					<%--                          <i class="ri-lock-line"></i>--%>
					<%--                        </div>--%>
					<%--                        <div class="media-body ml-3">--%>
					<%--                          <h6 class="mb-0 ">Privacy Settings</h6>--%>
					<%--                          <p class="mb-0 font-size-12">Control your privacy parameters.</p>--%>
					<%--                        </div>--%>
					<%--                      </div>--%>
					<%--                    </a>--%>
					<%--                    <div class="d-inline-block w-100 text-center p-3">--%>
					<%--                      <a class="bg-primary iq-sign-btn" href="sign-in.html" role="button">Sign out<i class="ri-login-box-line ml-2"></i></a>--%>
					<%--                    </div>--%>
					<%--                  </div>--%>
					<%--                </div>--%>
					<%--              </div>--%>
					<%--            </li>--%>
				</ul>
			</div>
		</nav>

	</div>
</div>
