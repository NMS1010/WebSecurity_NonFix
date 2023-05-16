<%@include file="taglib.jsp"%>
<c:if test="${not empty message}">
  <div class="alert text-white bg-${alert}" role="alert" style="border-radius: 5px;">
    <div class="iq-alert-icon">
      <c:if test="${alert != 'danger'}">
        <i class="fa-solid fa-circle-check"></i>
      </c:if>

      <c:if test="${alert == 'danger'}">
        <i class="fa-solid fa-circle-exclamation"></i>
      </c:if>

    </div>
    <div class="iq-alert-text">${message}</div>
    <button type="button" class="close" data-dismiss="alert" aria-label="Close">
      <i class="fa-solid fa-circle-xmark"></i>
    </button>
  </div>
</c:if>