<%@ page language="java" contentType="text/html; charset=UTF-8"
	pageEncoding="UTF-8"%>
<%@include file="/common/taglib.jsp"%>
<html>
<head>
<title>HomePage</title>
<%@include file="/common/link-css-js.jsp"%>

<link rel="stylesheet"
	href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
<link
	href="https://cdn.jsdelivr.net/npm/remixicon@2.5.0/fonts/remixicon.css"
	rel="stylesheet">
</head>
<body>
	<%@include file="/common/web/navbar.jsp"%>
	<div class="wrapper">

		<%-- <%@include file="/common/web/sidebar.jsp"%> --%>
		<dec:body />
	</div>
	<%@include file="/common/footer.jsp"%>
</body>
<script>
	<c:if test="${not empty sessionScope.USER_MODEL}">
		const url = "<c:url value='/web/book/search'/>";
	</c:if>
	<c:if test="${empty sessionScope.USER_MODEL}">
		const url = "<c:url value='/home/book/search'/>";
	</c:if>

	function changeFormAction() {
		var category = "?category="
		var store = "&store="
		var rating = "&rating="
		var minPrice = "&minPrice="
		var maxPrice = "&maxPrice="
		var searchkeyword = "&search="
				+ document.getElementById("searchinput").value;
		if (document.getElementById("searchBook")) {
			category = category
					+ document.getElementById("categorySearch").value;
			store = store + document.getElementById("storeSearch").value;
			rating = rating + document.getElementById("ratingSearch").value;
			minPrice = minPrice
					+ document.getElementById("minPriceSearch").value;
			maxPrice = maxPrice
					+ document.getElementById("maxPriceSearch").value;
			document.getElementById("searchBook").action = url + category
					+ store + rating + minPrice + maxPrice + searchkeyword
		} else {
			category = category + 0
			store = store + 0
			rating = rating + -1
			minPrice = minPrice + 0
			maxPrice = maxPrice + 1000000
			document.getElementById("searchbutton").formAction = url + category
					+ store + rating + minPrice + maxPrice + searchkeyword;
		}
	}
</script>
</html>
