<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@include file="/common/taglib.jsp"%>

<div id="content-page" class="content-page"
	style="margin-left: 0; padding-left: 100px !important; padding-right: 100px !important; background-color: #efefef">
	<div class="container-fluid">
		<div class="row">
			<div class="col-sm-12">
				<div class="d-block text-center">
					<h2 class="mb-3">TRANG KHÁCH HÀNG</h2>
					<div class="w-100 iq-search-filter">
						<form action="search" class="searchbox mt-3" method="post">
							<ul
								class="list-inline p-0 m-0 row justify-content-center search-menu-options">
								<li class="search-menu-opt">
									<div
										class="iq-search-bar search-book d-flex align-items-center">
										<input name="searchkeyword" type="text" class="text search-input"
											placeholder="Nhập tên người dùng cần tìm..."> <a
											class="search-link" href="#"><i class="ri-search-line"></i></a>
										<button type="submit" class="btn btn-primary search-data ml-2">Tìm
											kiếm</button>
									</div>
								</li>
							</ul>
						</form>
					</div>
				</div>
				<div class="iq-card">
					<div class="iq-card-body">
						<div class="table-responsive">
							<table id="user-list-table" class="table table-striped mt-4"
								role="grid" aria-describedby="user-list-page-info">
								<thead>
									<tr>
										<th>Profile</th>
										<th>Tên</th>
										<th>Số điện thoại</th>
										<th>Email</th>
										<th>Xem chi tiết</th>
									</tr>
								</thead>
								<tbody>
									<c:forEach items="${userListSearch}" var="user">
										<tr>
											<td class="text-center"><img
												class="rounded img-fluid avatar-40" src="images/user/01.jpg"
												alt="profile"></td>
											<td>${user.firstname} ${user.lastname}</td>
											<td>${user.phone}</td>
											<td>${user.email}</td>																				
											<td><a href="<c:url value='/web/user/profile?id=${user.id}'/>" ><span class="badge iq-bg-primary">Xem chi tiết</span></a></td>
										</tr>
									</c:forEach>
								</tbody>
							</table>
						</div>
						<div class="row justify-content-between mt-3">
							<div id="user-list-page-info" class="col-md-6">
								<span>Showing 1 to 5 of 5 entries</span>
							</div>
							<div class="col-md-6">
								<nav aria-label="Page navigation example">
									<ul class="pagination justify-content-end mb-0">
										<li class="page-item disabled"><a class="page-link"
											href="#" tabindex="-1" aria-disabled="true">Previous</a></li>
										<li class="page-item active"><a class="page-link"
											href="#">1</a></li>
										<li class="page-item"><a class="page-link" href="#">2</a></li>
										<li class="page-item"><a class="page-link" href="#">3</a></li>
										<li class="page-item"><a class="page-link" href="#">Next</a>
										</li>
									</ul>
								</nav>
							</div>
						</div>
					</div>
				</div>
			</div>
		</div>
	</div>
</div>