<%@ page language="java" contentType="text/html; charset=UTF-8"
         pageEncoding="UTF-8" %>
<%@include file="/common/taglib.jsp"%>
<c:url value="/admin/product/prohibit?search=" var="urlPro"/>
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
                <h4 class="card-title">QUẢN LÝ TẤT CẢ SẢN PHẨM BỊ CẤM BÁN</h4>
              </div>
            </div>
            <div class="iq-card-body">
              <div class="table-responsive">
                <div class="d-flex align-items-center justify-content-between">
                <h6>Tổng sản phẩm bị cấm bán: ${productList.size() + totalItemInPage*(tag-1)} / ${countP}</h6>
                  <div>
                    <label>Tìm kiếm theo tên sản phẩm:</label>
                    <div class="iq-card-transparent mb-0">
                      <div class="d-block">
                        <div class="w-100 iq-search-filter">
                          <div class="iq-search-bar search-book d-flex align-items-center">
                            <form action="#" class="searchbox m-0">
                              <input type="text" class="text search-input"
                                     placeholder="Nhập tên sản phẩm cần tìm..."
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
                <table id="user-list-table" class="table table-striped table-bordered mt-4" role="grid"
                       aria-describedby="user-list-page-info">
                  <thead>
                  <tr class="text-center">
                    <th>STT</th>
                    <th>Tên sản phẩm</th>
                    <th>Mô tả</th>
                    <th>Giá</th>
                    <th>Số lượng đã bán</th>
                    <th>Chuyển mở</th>
                  </tr>
                  </thead>
<%--                  Hide--%>
                  <input type="hidden" id="productId" value="">
                  <input type="hidden" id="state" value="">
                  <tbody>
                  <c:forEach items="${productList}" var="productList" varStatus="STT" >
                    <tr class="text-center">
                      <td>${STT.index + 1 + totalItemInPage*(tag-1)}</td>
                      <td>${productList.name}</td>
                      <td>${productList.description}</td>
                      <td>${productList.price}</td>
                      <td>${productList.sold}</td>
                      <td>
                        <div class="d-flex align-items-center list-user-action justify-content-center">
                      <a href="" onclick="ClickIcon(event, 'true')" id="${productList.id}" data-toggle="modal" data-target="#deleteModal"  class="bg-primary p-3 d-flex justify-content-center align-items-center"><i id="${productList.id}" class="fa-solid fa-door-open"></i></a>
                        </div>
                      </td>
                    </tr>
                  </c:forEach>
                  </tbody>
                </table>
              </div>
              <div class="col-sm-12 col-md-4 mx-auto">
                <div class="dataTables_paginate paging_simple_numbers">
                  <ul class="pagination justify-content-center">
                    <li class="paginate_button page-item ${tag == 1 ? "disabled" : ""}">
                      <a href="${pageContext.request.contextPath}/admin/product/prohibit?index=${tag - 1}"
                         class="page-link">Previous
                      </a>
                    </li>
                    <c:forEach begin="1" end="${endP}" var="i">
                      <li class="paginate_button page-item ${i == tag ? "active" : ""}">
                        <a href="${pageContext.request.contextPath}/admin/product/prohibit?&index=${i}"
                           class="page-link">${i}</a>
                      </li>
                    </c:forEach>
                    <li class="paginate_button page-item ${tag == endP ? "disabled" : ""}">
                      <a href="${pageContext.request.contextPath}/admin/product/prohibit?index=${tag + 1}"
                         class="page-link">Next</a>
                    </li>
                  </ul>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
      <div class="modal fade" id="deleteModal" tabindex="-1" role="dialog" aria-labelledby="deleteModalLabel" aria-hidden="true">
        <div class="modal-dialog" role="document">
          <div class="modal-content">
            <div class="modal-header">
              <h5 class="modal-title" id="deleteModalLabel">Gỡ cấm bán sản phẩm</h5>
              <button type="button" class="close" data-dismiss="modal" aria-label="Close">
                <span aria-hidden="true">&times;</span>
              </button>
            </div>
            <div class="modal-body" id="deleteModalBody">
              Bạn có thực sự muốn gỡ cấm bán không?
            </div>
            <div class="modal-footer">
              <button type="button" class="btn btn-secondary" data-dismiss="modal">Huỷ</button>
              <button type="button" onclick="Action()" class="btn btn-primary" data-dismiss="modal">Chắc chắn</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
<script type="text/javascript">
  function ClickIcon(e, state) {
    e.preventDefault();
    const productId = e.target.id;
    document.getElementById('productId').value = productId;
    document.getElementById('state').value = state;
  }
  function Action() {
    const productId = document.getElementById('productId').value;
    const state = document.getElementById('state').value;
    window.location.href = 'ban?productId='+productId.toString() + '&state='+ state;
  }
  function Search() {
    const key = $('#input-search').val();
    window.location.href = "${urlProc}" + key;
  }
</script>
</body>
</html>
