<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%@include file="/common/taglib.jsp"%>
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Insert title here</title>
</head>
<body>
		<div style="background-image: linear-gradient(to right top, #0dd6b8, #85e79a, #fffefc)">
				<section class="sign-in-page">
						<div class="container p-0">
								<div class="row no-gutters height-self-center">
										<div class="col-sm-12 align-self-center page-content rounded">
												<div class="row m-0">
														<div class="col-sm-12 sign-in-page-data">
																<div class="sign-in-from" style="padding: 0">
																		<%@include file="/common/info.jsp"%>
																</div>
																<div class="sign-in-from bg-white rounded">
																		<h3 class="mb-0 text-primary">Nhập mã để xác nhận</h3>
																		<form method="post" class="mt-4">
																				<div class="form-group">
																						<label for="exampleInputEmail1">Mã xác nhận</label> 
																						<input type="text" class="form-control mb-0 text-black font-size-20 font-weight-bold"
																								name="code" placeholder="Nhập mã"
																						>
																				</div>
																				<div class="d-flex justify-content-end">
																						<div class="d-block" style="margin-right: 10px;">
																								<button formaction="<c:url value="/signup?action=verify"/>" class="btn btn-white">Xác
																										nhận</button>
																						</div>
																						<div class="d-block">
																								<a href="<c:url value="/home"/>" class="btn btn-danger">Hủy</a>
																						</div>
																				</div>
																		</form>
																</div>
														</div>
												</div>
										</div>
								</div>
						</div>
				</section>
		</div>
</body>
</html>