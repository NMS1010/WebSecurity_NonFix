<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@include file="/common/taglib.jsp"%>
<c:url value="/vendor/review?star=" var="urlReview" />
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Insert title here</title>
</head>
<body>
		<div class="container-fluid">
				<div class="row">
						<div class="col-lg-12">
								<%@include file="/common/info.jsp"%>
								<div class="iq-card">
										<div class="iq-card-body p-0">
												<div class="iq-edit-list">
														<ul class="iq-edit-profile d-flex nav nav-pills">
																<li class="col-md-2 p-0"><a class="nav-link ${starResp=='all'?'active':''}"
																		href="<c:url value="/vendor/review?star=all"/>"
																> Tất cả </a></li>
																<li class="col-md-2 p-0"><a class="nav-link ${starResp=='5'?'active':''}"
																		href="<c:url value="/vendor/review?star=5"/> "
																> 5 Sao </a></li>
																<li class="col-md-2 p-0"><a class="nav-link ${starResp=='4'?'active':''}"
																		href="<c:url value="/vendor/review?star=4"/> "
																> 4 Sao </a></li>
																<li class="col-md-2 p-0"><a class="nav-link ${starResp=='3'?'active':''}"
																		href="<c:url value="/vendor/review?star=3"/> "
																> 3 Sao </a></li>
																<li class="col-md-2 p-0"><a class="nav-link ${starResp=='2'?'active':''}"
																		href="<c:url value="/vendor/review?star=2"/> "
																> 2 Sao </a></li>
																<li class="col-md-2 p-0"><a class="nav-link ${starResp=='1'?'active':''}"
																		href="<c:url value="/vendor/review?star=1"/> "
																> 1 Sao </a></li>
														</ul>
												</div>
										</div>
								</div>
						</div>
						<div class="col-lg-12">
								<div class="row">
										<div class="form-group col-sm-6">
												<label>Tìm kiếm theo tên sách:</label>
												<div class="iq-card-transparent mb-0">
														<div class="d-block">
																<div class="w-100 iq-search-filter">
																		<div class="iq-search-bar search-book d-flex align-items-center">
																				<form action="#" class="searchbox">
																						<input type="text" class="text search-input" placeholder="Nhập tên sản phẩm cần tìm..."
																								id="input-search" name="" value="${search}"
																						>
																				</form>
																				<button id="btn-search" onclick="Search()" class="btn btn-warning search-data ml-2 mb-3">Tìm</button>
																		</div>
																</div>
														</div>
												</div>
										</div>
										<div class="form-group col-sm-6">
												<div class="form-group"></div>
										</div>
								</div>
								<div class="iq-edit-list-data">
										<div class="tab-content">
												<div class="tab-pane fade active show" id="allorder" role="tabpanel">
														<div class="iq-card">
																<div class="iq-card-header d-flex justify-content-between">
																		<div class="iq-header-title">
																				<h4 class="card-title">Đánh giá của người dùng</h4>
																		</div>
																</div>
																<div class="iq-card-body">
																		<div class="table-responsive">
																				<table id="table-product" class="data-tables table table-striped table-bordered" style="width: 100%">
																						<thead>
																								<tr>
																										<th>Ảnh</th>
																										<th>Tên sách</th>
																										<th>Đánh giá của Người mua</th>
																								</tr>
																						</thead>
																						<tbody id="list-product">
																								<c:forEach items="${reviews}" var="review">
																										<tr class="item-product">
																												<td style="width: 100px; min-height: 100px;"><c:url
																																value="/image?fname=${review.product.getImages().get(0).getName()}&type=product"
																																var="imgUrl"
																														></c:url> <img class="img-fluid rounded" src="${imgUrl}" alt="pic"
																														style="width: 100%; object-fit: cover;"
																												></td>
																												<td>${review.product.getName()}</td>
																												<td>
																														<div class="d-flex align-items-center mb-1">
																																<c:choose>
																																		<c:when test="${review.user.avatar != null}">
																																				<c:url value="/image?fname=${review.user.avatar}&type=user" var="imgAvatar"></c:url>
																																		</c:when>
																																		<c:otherwise>
																																				<c:url value='/template/images/default-avatar.png' var="imgAvatar" />
																																		</c:otherwise>
																																</c:choose>
																																<img class="rounded-circle img-fluid avatar-40" src="${imgAvatar}" alt="profile">
																																<p class="mt-3 ml-1 mr-3">${review.user.firstname} ${review.user.lastname}</p>
																																<div class="font-size-13 text-warning">
																																	<c:forEach var="i" begin="1" end="5">
																																		<c:if test="${i <= review.stars }">
																																				<i class="fa fa-star"></i>
																																		</c:if>
																																		<c:if test="${i > review.stars }">
																																				<i class="fa fa-star-o"></i>
																																		</c:if>
																																</c:forEach>
																																</div>
																														</div> ${review.content}
																												</td>
																										</tr>
																								</c:forEach>
																						</tbody>
																				</table>
																		</div>
																</div>
														</div>
												</div>
										</div>
								</div>
						</div>
				</div>
				<div class="row">
						<div class="col-sm-12 col-md-8"></div>
						<div class="col-sm-12 col-md-4">
								<div class="dataTables_paginate paging_simple_numbers">
										<ul class="pagination">
												<li class="paginate_button page-item ${tag <= 1 ? "disabled" : ""}"><a
														href="${pageContext.request.contextPath}/vendor/review?star=${starResp}&index=${tag - 1}"
														class="page-link"
												>Previous </a></li>
												<c:forEach begin="1" end="${endP}" var="i">
														<li class="paginate_button page-item ${i == tag ? "active" : ""}"><a
																href="${pageContext.request.contextPath}/vendor/review?star=${starResp}&index=${i}" class="page-link"
														>${i}</a></li>
												</c:forEach>
												<li class="paginate_button page-item ${tag >= endP ? "disabled" : ""}"><a
														href="${pageContext.request.contextPath}/vendor/review?star=${starResp}&index=${tag + 1}"
														class="page-link"
												>Next</a></li>
										</ul>
								</div>
						</div>
				</div>
		</div>
		<script>
			function Search() {
				const key = $('#input-search').val();
				window.location.href = "${urlReview}" + "${starResp}"
						+ "&search=" + key;
			}
		</script>
</body>
</html>