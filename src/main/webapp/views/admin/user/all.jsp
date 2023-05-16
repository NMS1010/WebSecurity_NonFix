<%@ page language="java" contentType="text/html; charset=UTF-8"
         pageEncoding="UTF-8" %>
<%@include file="/common/taglib.jsp"%>
<c:url value="/admin/user/all?search=" var="urlProc" />
<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport"
        content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
  <meta http-equiv="X-UA-Compatible" content="ie=edge">
  <title>Document</title>
</head>
<body>
<div id="loading">
  <div id="loading-center">
  </div>
</div>
<!-- loader END -->
<!-- Wrapper Start -->
<div class="wrapper">
  <div id="content-page" class="content-page">
    <div class="container-fluid">
      <div class="row">
        <div class="col-sm-12">
          <div class="iq-card">
            <div class="iq-card-header d-flex justify-content-center">
              <div class="iq-header-title">
                <h4 class="card-title">QUẢN LÝ TẤT CẢ NGƯỜI DÙNG</h4>
              </div>
            </div>

            <div class="iq-card-body">
              <div class="table-responsive">
                <a href="<c:url value="/admin/download-report?type=user"/> "
                   class="text-dark" style="display: block; margin-left: 10px; margin-bottom: 12px;">
                  Tải báo cáo
                  <i class="fa-solid fa-download"></i>
                </a>
                <div class="d-flex align-items-center justify-content-between">
                  <h6>Tổng người dùng: ${userList.size() + totalItemInPage*(tag-1)} / ${countP}</h6>

                  <div>
                    <label>Tìm kiếm theo tên khách hàng:</label>
                    <div class="iq-card-transparent mb-0">
                      <div class="d-block">
                        <div class="w-100 iq-search-filter">
                          <div class="iq-search-bar search-book d-flex align-items-center">
                            <form action="#" class="searchbox m-0">
                              <input type="text" class="text search-input"
                                     placeholder="Nhập tên khách hàng cần tìm..."
                                     id="input-search"
                                     name=""
                                     value="${search}"
                              >
                            </form>
                            <button id="btn-search" onclick="Search()"
                                    class="btn btn-warning search-data ml-2">Tìm</button>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                <table id="user-list-table" class="table table-striped table-bordered" role="grid"
                       aria-describedby="user-list-page-info">
                  <thead>
                  <tr class="text-center">
                    <th>STT</th>
                    <th>Họ và tên đệm</th>
                    <th>Tên</th>
                    <th>CMND/CCCD</th>
                    <th>Email</th>
                    <th>Phone</th>
                  </tr>
                  </thead>
                  <tbody>
                  <c:forEach items="${userList}" var="users" varStatus="STT" >
                    <tr class="text-center">
                      <td>${STT.index + 1 + totalItemInPage*(tag-1)}</td>
                      <td>${users.lastname }</td>
                      <td>${users.firstname }</td>
                      <td>${users.id_card }</td>
                      <td>${users.email }</td>
                      <td>${users.phone }</td>
                    </tr>
                  </c:forEach>
                  </tbody>
                </table>
              </div>
              <div class="col-sm-12 col-md-4 mx-auto">
                <div class="dataTables_paginate paging_simple_numbers">
                  <ul class="pagination justify-content-center">
                    <li class="paginate_button page-item ${tag == 1 ? "disabled" : ""}">
                      <a href="${pageContext.request.contextPath}/admin/user/all?index=${tag - 1}"
                         class="page-link">Previous
                      </a>
                    </li>
                    <c:forEach begin="1" end="${endP}" var="i">
                      <li class="paginate_button page-item ${i == tag ? "active" : ""}">
                        <a href="${pageContext.request.contextPath}/admin/user/all?&index=${i}"
                           class="page-link">${i}</a>
                      </li>
                    </c:forEach>
                    <li class="paginate_button page-item ${tag == endP ? "disabled" : ""}">
                      <a href="${pageContext.request.contextPath}/admin/user/all?index=${tag + 1}"
                         class="page-link">Next</a>
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
<script>
  function Search() {
    const key = $('#input-search').val();
    window.location.href = "${urlProc}" + key;
  }
</script>
</body>
</html>

