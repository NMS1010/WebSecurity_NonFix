<%@ page language="java" contentType="text/html; charset=UTF-8"
         pageEncoding="UTF-8" %>
<%@include file="/common/taglib.jsp"%>
<c:url value="/admin/transaction" var="urlList"/>

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
                <h4 class="card-title">QUẢN LÝ TẤT CẢ CÁC GIAO DỊCH</h4>
              </div>
            </div>
            <div class="iq-card-body">
              <div class="table-responsive">
                <a href="<c:url value="/admin/download-report?type=transaction"/> "
                   class="text-dark" style="display: block; margin-left: 10px; margin-bottom: 12px;">
                  Tải báo cáo
                  <i class="fa-solid fa-download"></i>
                </a>
                <div class="d-flex align-items-center justify-content-between">
                  <h6>Tổng giao dịch: ${transactionList.size() + totalItemInPage*(tag-1)} / ${countP}</h6>
                  <div>
                    <label>Tìm kiếm theo tên người dùng:</label>
                    <div class="iq-card-transparent mb-0">
                      <div class="d-block">
                        <div class="w-100 iq-search-filter">
                          <div class="iq-search-bar search-book d-flex align-items-center">
                            <form action="#" class="searchbox m-0">
                              <input type="text" class="text search-input"
                                     placeholder="Nhập tên người dùng cần tìm..."
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
                <select id="selectCate" class="form-control w-25">
                  <c:forEach items="${storesList}" var="storesList">
                    <option value="${storesList.id}"
                      ${storesList.id == storeId ? "selected" : ""}
                    >
                        ${storesList.name}
                    </option>
                  </c:forEach>
                </select>
                <table id="user-list-table" class="table table-striped table-bordered mt-4" role="grid"
                       aria-describedby="user-list-page-info">
                  <thead>
                  <tr class="text-center">
                    <th>STT</th>
                    <th>Tên người dùng</th>
                    <th>Số tiền</th>
                    <th>Nội dung</th>
                    <th>Thời gian</th>
                  </tr>
                  </thead>
                  <tbody>
                  <c:forEach items="${transactionList}" var="transactionList" varStatus="STT" >
                    <tr class="text-center">
                      <td>${STT.index + 1 + totalItemInPage*(tag-1)}</td>
                      <td>${transactionList.nameUser}</td>
                      <td>${transactionList.amount}</td>
                      <td>${transactionList.isUpString == 'Nạp' ? 'Rút' : 'Nạp'}</td>
                      <td>${transactionList.createdAt.toString()}</td>
                    </tr>
                  </c:forEach>
                  </tbody>
                </table>
              </div>
              <div class="col-sm-12 col-md-4 mx-auto">
                <div class="dataTables_paginate paging_simple_numbers">
                  <ul class="pagination justify-content-center">
                    <li class="paginate_button page-item ${tag == 1 ? "disabled" : ""}">

                      <a href="${pageContext.request.contextPath}/admin/transaction?storeId=${storeId}&index=${tag - 1}"

                         class="page-link">Previous
                      </a>
                    </li>
                    <c:forEach begin="1" end="${endP}" var="i">
                      <li class="paginate_button page-item ${i == tag ? "active" : ""}">
                        <a href="${pageContext.request.contextPath}/admin/transaction?storeId=${storeId}&index=${i}"
                           class="page-link">${i}</a>
                      </li>
                    </c:forEach>
                    <li class="paginate_button page-item ${tag == endP ? "disabled" : ""}">

                      <a href="${pageContext.request.contextPath}/admin/transaction?storeId=${storeId}&index=${tag + 1}"

                         class="page-link">Next</a>
                    </li>
                  </ul>
                </div>
              </div>
              <span>*Rút: Rút từ ví cửa hàng về ví chủ cửa hàng.</span><br />
              <span>*Nạp: Nạp vào ví cửa hàng khi một đơn hàng được giao thành công.</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
<script type="text/javascript">
  $('#selectCate').change(function () {
    const storeId = $("#selectCate option:selected").val();
    window.location.href = "${urlList}?storeId=" + storeId;
  });
  function Search() {
    const key = $('#input-search').val();
    const storeId = $("#selectCate option:selected").val();
    window.location.href = "${urlList}?storeId=" + storeId + "&search=" + key;
  }
</script>
</body>
</html>