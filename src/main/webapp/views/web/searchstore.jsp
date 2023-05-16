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
						<h2 class="mb-3">Tìm kiếm cửa hàng</h2>
						<div class="w-100 iq-search-filter">
							<form action="search" class="searchbox mt-3" method="post">
								<ul
									class="list-inline p-0 m-0 row justify-content-center search-menu-options">
									<li class="search-menu-opt"><label>Cửa hàng</label>
										<div
											class="iq-search-bar search-book d-flex align-items-center">
											<div class="searchbox mt-3 d-flex">
												<input name="searchkeyword" type="text"
													class="text search-input"
													placeholder="Nhập tên cửa hàng bạn muốn tìm kiếm...">
												<a class="search-link" href="#"><i
													class="ri-search-line"></i></a>
												<button type="submit"
													class="btn btn-primary search-data ml-2">Tìm kiếm</button>
											</div>
										</div></li>
								</ul>
							</form>
						</div>
					</div>
				</div>
				<div class="iq-card">
					<div class="iq-card-body">
						<div class="row">
							<c:if test="${empty storeSearchList}">
								<div class="col-lg-12 d-flex justify-content-center">
									<img style="width: 30%"
										src="<c:url value="/template/images/notfoundproduct.png"/>" />
								</div>
								<div class="col-lg-12 text-center mb-5">
									<span class="text-second text-uppercase font-size-20">Không
										tìm thấy tên cửa hàng bạn cần tìm rồi.</span>
								</div>

							</c:if>
							<c:forEach items="${storeSearchList}" var="store">
								<div class="col-sm-6 col-md-4 col-lg-3">
									<div
										class="iq-card iq-card-block iq-card-stretch iq-card-height search-bookcontent">
										<div class="iq-card-body p-0">
											<div class="d-flex align-items-center">
												<div
													class="col-6 p-0 position-relative image-overlap-shadow">
													<a href="javascript:void();"> <c:url
															value="/image?fname=${store.getImages().get(0).getName()}&type=store"
															var="imgUrl"></c:url> <img
														class="img-fluid rounded w-100"
														style="object-fit: contain; height: 25vh; width: 20vh"
														src="${imgUrl}" alt="">
													</a>
													<div class="view-book">
														<c:if test="${not empty sessionScope.USER_MODEL}">
															<a
															href="<c:url value ='/web/store/detail?id=${store.id}'/>"
															class="btn btn-sm btn-white">Xem chi tiết</a>
														</c:if>
														<c:if test="${empty sessionScope.USER_MODEL}">
															<a
															href="<c:url value ='/home/store/detail?id=${store.id}'/>"
															class="btn btn-sm btn-white">Xem chi tiết</a>
														</c:if>
														
													</div>
												</div>

												<div class="col-6">
													<div class="mb-2">
														<h6 class="mb-1">${store.name}</h6>
														<c:forEach items="${ownerSearchList}" var="owner">
															<c:if test="${owner.id == store.ownerID}">
																<p class="font-size-13 line-height mb-1">${owner.firstname}
																	${owner.lastname}</p>
															</c:if>
														</c:forEach>
														<div class="d-block">
															<span class="font-size-13 text-warning"> <c:forEach
																	var="i" begin="1" end="5">
																	<c:if test="${i <= store.rating }">
																		<i class="fa fa-star"></i>
																	</c:if>
																	<c:if test="${i > store.rating }">
																		<i class="fa fa-star-o"></i>
																	</c:if>
																</c:forEach>
															</span>
														</div>
													</div>
													<div class="price d-flex align-items-center">
														<span class="pr-1">${store.bio}</span>
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