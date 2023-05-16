<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@include file="/common/taglib.jsp"%>

<div id="content-page" class="content-page"
	style="margin-left: 0; padding-left: 100px !important; padding-right: 100px !important; background-color: #efefef">
	<div class="container-fluid">
		<div class="row">
			<div class="col-sm-12">
				<div class="iq-card">
					<div class="iq-card-header d-flex justify-content-between">
						<div class="iq-header-title">
							<h4 class="card-title">Đơn mua</h4>
						</div>
					</div>
					<div class="iq-card-body">
						<div class="table-responsive">
							<table id="datatable" class="table">
								<thead>
									<tr>
										<th>Thời gian</th>
										<th>Thuộc cửa hàng</th>
										<th>Tổng tiền</th>
										<th>Số lượng</th>
										<th>Trạng thái</th>
										<th>Chi tiết</th>
									</tr>
								</thead>
								<tbody>
									<c:forEach items="${ordersList}" var="orders">
										<tr>
											<td>${orders.createdAt}</td>
											<td>${orders.store.name}</td>
											<td>${orders.amountFromUser}</td>
											<td>${orders.ordersItem.size()}</td>
											<c:if test="${orders.status == 'not-processed'}">
												<td>Chờ xử lý</td>
											</c:if>
											<c:if test="${orders.status == 'shipped'}">
												<td>Đang giao</td>
											</c:if>
											<c:if test="${orders.status == 'delivered'}">
												<td>Đã giao</td>
											</c:if>
											<c:if test="${orders.status == 'cancelled'}">
												<td>Đã hủy</td>
											</c:if>
											<td><a
												href="<c:url value="/web/order/item/list?id=${orders.id}"/>"
												class="text-primary"> Chi tiết </a></td>
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