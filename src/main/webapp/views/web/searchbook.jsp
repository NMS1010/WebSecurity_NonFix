<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@include file="/common/taglib.jsp"%>

<div id="content-page" class="content-page"
	style="margin-left: 0; padding-left: 100px !important; padding-right: 100px !important; background-color: #efefef">
	<div class="container-fluid">
		<div class="row">
			<div class="col-lg-12">
				<div class="iq-card-transparent mb-0">
					<div class="d-block text-center">

						<div class="w-100 iq-search-filter">
							<form id="searchBook" action="#" class="searchbox mt-3"
								method="post">
								<ul
									class="list-inline p-0 m-0 row justify-content-center search-menu-options">
									<li class="search-menu-opt mt-3">
										<div class="iq-dropdown">
											<div class="form-group mb-0">
												<label>Danh mục</label> <select id="categorySearch"
													onchange="changeFormAction();this.form.submit()"
													class="form-control form-search-control bg-white border-0">

													<c:choose>
														<c:when
															test="${(empty categorySearch) || (categorySearch == 0)}">
															<option selected value="0">Tất cả</option>
														</c:when>
														<c:otherwise>
															<option value="0">Tất cả</option>
														</c:otherwise>
													</c:choose>
													<c:forEach items="${categoryList}" var="category">
														<c:choose>
															<c:when test="${categorySearch == category.id}">
																<option selected value="${category.id}">${category.name}</option>
															</c:when>
															<c:otherwise>
																<option value="${category.id}">${category.name}</option>
															</c:otherwise>
														</c:choose>

													</c:forEach>


												</select>
											</div>
										</div>
									</li>
									<li class="search-menu-opt mt-3">
										<div class="iq-dropdown">
											<div class="form-group mb-0">
												<label>Cửa hàng</label> <select id="storeSearch"
													onchange="changeFormAction();this.form.submit()"
													class="form-control form-search-control bg-white border-0">
													<c:choose>
														<c:when
															test="${(empty storeSearch) || (storeSearch == 0)}">
															<option selected value="0">Tất cả</option>
														</c:when>
														<c:otherwise>
															<option value="0">Tất cả</option>
														</c:otherwise>
													</c:choose>
													<c:forEach items="${storeList}" var="store">
														<c:choose>
															<c:when test="${storeSearch == store.id}">
																<option selected value="${store.id}">${store.name}</option>
															</c:when>
															<c:otherwise>
																<option value="${store.id}">${store.name}</option>
															</c:otherwise>
														</c:choose>

													</c:forEach>
												</select>
											</div>
										</div>
									</li>
									<li class="search-menu-opt mt-3">
										<div class="iq-dropdown">
											<div class="form-group mb-0">
												<label>Rating</label> <select id="ratingSearch"
													onchange="changeFormAction();this.form.submit()"
													class="form-control form-search-control bg-white border-0">

													<option
														<c:if test="${(empty rating) || (rating == -1)}">selected</c:if>
														value="-1">Tất cả</option>
													<option <c:if test="${rating == 0}">selected</c:if>
														value="0">0</option>
													<option <c:if test="${rating == 1}">selected</c:if>
														value="1">1</option>
													<option <c:if test="${rating == 2}">selected</c:if>
														value="2">2</option>
													<option <c:if test="${rating == 3}">selected</c:if>
														value="3">3</option>
													<option <c:if test="${rating == 4}">selected</c:if>
														value="4">4</option>
													<option <c:if test="${rating == 5}">selected</c:if>
														value="5">5</option>
												</select>
											</div>
										</div>
									</li>
									<li class="search-menu-opt mt-3">
										<div class="iq-dropdown">
											<div class="form-group mb-0">
												<label>Giá tối thiểu</label> <select id="minPriceSearch"
													onchange="changeFormAction();this.form.submit()"
													class="form-control form-search-control bg-white border-0">
													<option
														<c:if test="${(empty minPrice) || (minPrice == 0)}">selected</c:if>
														value="0">0</option>
													<option <c:if test="${minPrice == 100000}">selected</c:if>
														value="100000">100.000 VNĐ</option>
													<option <c:if test="${minPrice == 200000}">selected</c:if>
														value="200000">200.000 VNĐ</option>
													<option <c:if test="${minPrice == 500000}">selected</c:if>
														value="500000">500.000 VNĐ</option>
													<option <c:if test="${minPrice == 800000}">selected</c:if>
														value="800000">800.000 VNĐ</option>
												</select>
											</div>
										</div>
									</li>
									<div class="m-2">
										<b>-</b>
									</div>
									<li class="search-menu-opt mt-3">
										<div class="iq-dropdown">
											<div class="form-group mb-0">
												<label>Giá tối đa</label> <select id="maxPriceSearch"
													onchange="changeFormAction();this.form.submit()"
													class="form-control form-search-control bg-white border-0">
													<option <c:if test="${maxPrice == 100000}">selected</c:if>
														value="100000">100.000 VNĐ</option>
													<option <c:if test="${maxPrice == 200000}">selected</c:if>
														value="200000">200.000 VNĐ</option>
													<option <c:if test="${maxPrice == 500000}">selected</c:if>
														value="500000">500.000 VNĐ</option>
													<option <c:if test="${maxPrice == 800000}">selected</c:if>
														value="800000">800.000 VNĐ</option>
													<option
														<c:if test="${(empty maxPrice) || (maxPrice == 1000000)}">selected</c:if>
														value="1000000">1.000.000 VNĐ</option>
												</select>
											</div>
										</div>
									</li>
								</ul>
							</form>
						</div>
					</div>
				</div>
				<div class="iq-card">
					<div class="iq-card-body">
						<div class="row">
							<c:if test="${empty searchProductList}">
								<div class="col-lg-12 d-flex justify-content-center">
									<img style="width: 30%"
										src="<c:url value="/template/images/notfoundproduct.png"/>" />
								</div>
								<div class="col-lg-12 text-center mb-5">
									<span class="text-second text-uppercase font-size-20">Rất
										tiếc! Không tìm thấy sản phẩm rồi.</span>
								</div>

							</c:if>
							<c:forEach items="${searchProductList}" var="product">
								<div class="col-sm-6 col-md-4 col-lg-3">
									<div
										class="iq-card iq-card-block iq-card-stretch iq-card-height search-bookcontent">
										<div class="iq-card-body p-0">
											<div class="d-flex align-items-center">
												<div
													class="col-6 p-0 position-relative image-overlap-shadow">
													<a href="javascript:void();"><c:url
															value="/image?fname=${product.getImages().get(0).getName()}&type=product"
															var="imgUrl"></c:url> <img
														class="img-fluid rounded w-100"
														style="object-fit: contain; height: 25vh; width: 20vh"
														src="${imgUrl}" alt=""></a>
													<div class="view-book">
														<c:if test="${not empty sessionScope.USER_MODEL}">
															<a
																href="<c:url value ='/web/book/detail?id=${product.id}'/>"
																class="btn btn-sm btn-white">Xem chi tiết</a>
														</c:if>
														<c:if test="${empty sessionScope.USER_MODEL}">
															<a
																href="<c:url value ='/home/book/detail?id=${product.id}'/>"
																class="btn btn-sm btn-white">Xem chi tiết</a>
														</c:if>

													</div>
												</div>

												<div class="col-6">
													<div class="mb-2">
														<h6 class="mb-1">${product.name}</h6>
														<div class="d-block">
															<span class="font-size-13 text-warning"> <c:forEach
																	var="i" begin="1" end="5">
																	<c:if test="${i <= product.rating }">
																		<i class="fa fa-star"></i>
																	</c:if>

																	<c:if test="${i > product.rating }">
																		<i class="fa fa-star-o"></i>
																	</c:if>
																</c:forEach>
															</span>
														</div>
													</div>
													<div class="price d-flex align-items-center">
														<!-- <span class="pr-1 old-price">$99</span> -->
														<h6>
															<b>${product.price}</b>
														</h6>
													</div>
													<div class="iq-product-action">
														<form method="post">
															<button
																style="border: none; background-color: transparent"
																formaction="<c:url value='/web/cart/item/create?id=${product.id}'/>"
																href="#">
																<i class="ri-shopping-cart-2-fill text-primary"></i>
															</button>
															<a href="#" class="ml-2"><i
																class="ri-heart-fill text-danger"></i></a>
														</form>
													</div>
												</div>
											</div>
										</div>
									</div>
								</div>
							</c:forEach>

						</div>
					</div>
				</div>
			</div>

		</div>
	</div>
</div>
