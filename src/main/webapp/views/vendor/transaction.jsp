<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@include file="/common/taglib.jsp"%>
<c:url value="/vendor/transaction" var="UrlTransaction" />
<html>
<head>
<title>Title</title>
</head>
<body>
		<div class="container-fluid">
				<div class="row">
						<div class="col-sm-12">
								<%@include file="/common/info.jsp"%>
								<div class="iq-card-transparent mb-0" style="margin-bottom: -16px; margin-top: 20px;">
										<div class="">
												<div class="w-100 iq-search-filter d-flex justify-content-sm-between">
														<div class="iq-search-bar search-book d-flex align-items-center">
																<label>Ngày giao dịch:</label>
																<form style="margin-left: 10px">
																		<input type="date" class="search-input" id="date-start" required value="${dateStart}">
																</form>
																<span style="height: 45px; font-size: 20px; margin-left: 10px;">-</span>
																<form style="margin-left: 10px">
																		<input type="date" class="search-input" id="date-end" required value="${dateEnd}"
																				onchange="CheckDate()"
																		>
																</form>
																<button onclick="Search()" class="btn btn-warning search-data ml-2 mb-3">Tìm</button>
														</div>
														
														<c:if test="${not empty storeExist}">
																<button class="btn btn-danger" data-target="#modal-wallet" data-toggle="modal" style="height: 45px">
																		<i class="fa-solid fa-money-bill-transfer text-white"></i> Rút tiền
																</button>
														</c:if>
												</div>
										</div>
								</div>
								<div class="iq-card">
										<div class="iq-card-header d-flex justify-content-between">
												<div class="iq-header-title">
														<h4 class="card-title">Danh sách các giao dịch của cửa hàng</h4>
												</div>
										</div>
										<div class="iq-card-body">
												<div class="table-responsive">
														<table id="table-product" class="data-tables table table-striped table-bordered" style="width: 100%">
																<thead>
																		<tr>
																				<th>No</th>
																				<th>Người dùng</th>
																				<th>Trạng thái</th>
																				<th>Số lượng</th>
																				<th>Thời gian</th>
																		</tr>
																</thead>
																<tbody id="list-product">
																		<c:forEach items="${transactions}" var="transaction" varStatus="index">
																				<tr class="item-product">
																						<td>${index.index + 1 + total*(tag-1)}</td>
																						<td>${transaction.nameUser}</td>
																						<td>${transaction.isUpString}</td>
																						<td>${transaction.amount}vnd</td>
																						<td>${transaction.createdAt}</td>
																				</tr>
																		</c:forEach>
																		<input type="hidden" id="productId" value="">
																		<input type="hidden" id="total" name="total" value="">
																		<input type="hidden" id="page" name="page" value="">
																		<input type="hidden" id="maxPageItem" name="maxPageItem" value="">
																		<input type="hidden" id="sortBy" name="sortBy" value="">
																		<input type="hidden" id="sortName" name="sortName" value="">
																</tbody>
														</table>
												</div>
										</div>
								</div>
						</div>
				</div>
				<!-- Paging -->
				<div class="row">
						<div class="col-sm-12 col-md-8"></div>
						<div class="col-sm-12 col-md-4">
								<div class="dataTables_paginate paging_simple_numbers">
										<ul class="pagination">
												<li class="paginate_button page-item ${tag == 1 ? "disabled" : ""}"><a
														href="${pageContext.request.contextPath}/vendor/transaction?index=${tag - 1}" class="page-link"
												>Previous </a></li>
												<c:forEach begin="1" end="${endP}" var="i">
														<li class="paginate_button page-item ${i == tag ? "active" : ""}"><a
																href="${pageContext.request.contextPath}/vendor/transaction?index=${i}" class="page-link"
														>${i}</a></li>
												</c:forEach>
												<li class="paginate_button page-item ${tag == endP ? "disabled" : ""}"><a
														href="${pageContext.request.contextPath}/vendor/transaction?index=${tag + 1}" class="page-link"
												>Next</a></li>
										</ul>
								</div>
						</div>
				</div>
				<!-- MODAL WITHDRAW -->
				<div class="modal fade" id="modal-wallet" tabindex="-1" role="dialog" aria-labelledby="exampleModalCenterTitle"
						aria-hidden="true"
				>
						<div class="modal-dialog modal-dialog-centered modal-sm" role="document">
								<div class="modal-content">
										<form action="<c:url value="/vendor/transaction"/>" method="post">
												<div class="modal-header">
														<h5 class="modal-title" id="exampleModalCenterTitle">Rút tiền</h5>
														<button type="button" class="close" data-dismiss="modal" aria-label="Close">
																<span aria-hidden="true">&times;</span>
														</button>
												</div>
												<div class="modal-body">
														<div class="mb-3"
																style="background-color: #f0f5f4; border-radius: 5px; padding: 5px 10px; line-height: 39px"
														>
																<i class="fa-solid fa-book text-primary"></i> <label style="margin: 0">Số dư Ví:</label> <span
																		class="font-weight-bold; ml-3" style="display: inline-block"
																>${wallet} vnđ</span>
														</div>
														<div>
																<label>Số tiền cần rút:</label> <input class="form-control font-weight-bold font-size-18" type="text"
																		placeholder="0đ" name="amount"
																>
														</div>
														<div class="mt-3">
																<span>Rút về Ví của: </span> <span class="font-weight-bold">${user}</span>
														</div>
												</div>
												<div class="d-flex justify-content-end" style="padding: 1rem; border-top: 1px solid #dee2e6">
														<button type="button" class="btn btn-secondary mr-3" data-dismiss="modal">Đóng</button>
														<button type="submit" class="btn btn-danger">Rút</button>
												</div>
										</form>
								</div>
						</div>
				</div>
		</div>
		<script>
			function Search() {
				const dateStart = $("#date-start").val()
				const dateEnd = $("#date-end").val();

				if (CheckDate()) {
					window.location.href = "${UrlTransaction}" + "?start="
							+ dateStart + "&end=" + dateEnd;
				} else {
					window.location.href = "${UrlTransaction}/notification?message=invalid_date"
				}
			}
			function CheckDate() {
				const dateStart = new Date($("#date-start").val())
				const dateEnd = new Date($("#date-end").val());
				if (dateStart == "Invalid Date" || dateEnd == "Invalid Date"
						|| dateStart > dateEnd) {
					return false;
				}
				return true;
			}
		</script>
</body>
</html>
