package com.mdk.controllers.user;

import static com.mdk.utils.AppConstant.CART_HEADER;
import static com.mdk.utils.AppConstant.CART_USER;
import static com.mdk.utils.AppConstant.COUNT_CART_HEADER;
import static com.mdk.utils.AppConstant.USER_MODEL;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.mdk.models.Cart;
import com.mdk.models.CartItem;
import com.mdk.models.Orders;
import com.mdk.models.OrdersItem;
import com.mdk.models.Product;
import com.mdk.models.Store;
import com.mdk.models.Transaction;
import com.mdk.models.User;
import com.mdk.services.ICartItemService;
import com.mdk.services.ICartService;
import com.mdk.services.IDeliveryService;
import com.mdk.services.IOrdersItemService;
import com.mdk.services.IOrdersService;
import com.mdk.services.IProductService;
import com.mdk.services.IStoreService;
import com.mdk.services.ITransactionService;
import com.mdk.services.IUserService;
import com.mdk.services.impl.CartItemService;
import com.mdk.services.impl.CartService;
import com.mdk.services.impl.DeliveryService;
import com.mdk.services.impl.OrdersItemService;
import com.mdk.services.impl.OrdersService;
import com.mdk.services.impl.ProductService;
import com.mdk.services.impl.StoreService;
import com.mdk.services.impl.TransactionService;
import com.mdk.services.impl.UserService;
import com.mdk.utils.SessionUtil;
@WebServlet(urlPatterns = { "/web/order/create", "/web/order/list", "/web/order/item/list" })
public class OrderController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	ICartService cartService = new CartService();
	IStoreService storeService = new StoreService();
	ICartItemService cartItemService = new CartItemService();
	IProductService productService = new ProductService();
	IDeliveryService deliveryService = new DeliveryService();
	IOrdersService ordersService = new OrdersService();
	IOrdersItemService ordersItemService = new OrdersItemService();
	IUserService userService = new UserService();
	ITransactionService transactionService = new TransactionService();

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String url = req.getRequestURL().toString();

		if (url.contains("/web/order/list")) {
			int id = ((User) SessionUtil.getInstance().getValue(req, "USERMODEL")).getId();
			List<Orders> ordersList = ordersService.findAllByUser(id);
			req.setAttribute("ordersList", ordersList);
			req.getRequestDispatcher("/views/web/orders.jsp").forward(req, resp);
		} else if (url.contains("web/order/item/list")) {
			int id = Integer.parseInt(req.getParameter("id"));
			Orders orders =  ordersService.findById(id);
			req.setAttribute("orders", orders);
			req.getRequestDispatcher("/views/web/ordersitem.jsp").forward(req, resp);
		}
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String url = req.getRequestURL().toString();

		if (url.contains("/web/order/create")) {
			insert(req, resp);
			insertItem(req, resp);
			insertTransaction(req,resp);
			changeSessionCart(req, resp);
			resp.sendRedirect(req.getContextPath() + "/web/cart");
		}

	}

	protected void insert(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		req.setCharacterEncoding("UTF-8");
		resp.setCharacterEncoding("UTF-8");

		Cart cart = (Cart) SessionUtil.getInstance().getValue(req, CART_USER);
		User user = (User) SessionUtil.getInstance().getValue(req, USER_MODEL);
		Store store = cart.getStore();
		int deliveryId = Integer.parseInt(req.getParameter("deliveryId"));
		String address = req.getParameter("address");
		String phone = req.getParameter("phone");

		Orders order = new Orders();
		order.setDeliveryId(deliveryId);
		order.setUserId(user.getId());
		order.setStoreId(store.getId());
		order.setAddress(address);
		order.setPhone(phone);

		Double deliveryPrice = deliveryService.findById(deliveryId).getPrice();
		Double amountFromUser = cart.getCartItems().stream().mapToDouble(o1 -> o1.getProduct().getPromotionalPrice())
				.sum() + deliveryPrice;
		Double amountToStore = amountFromUser - 0.025 * amountFromUser;
		Double amountToGD = amountFromUser * 0.025;

		order.setAmountFromUser(amountFromUser);
		order.setAmountToStore(amountToStore);
		order.setAmountToGD(amountToGD);

		ordersService.insert(order);
	}

	protected void insertItem(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		req.setCharacterEncoding("UTF-8");
		resp.setCharacterEncoding("UTF-8");

		User user = (User) SessionUtil.getInstance().getValue(req, USER_MODEL);
		Cart cart = (Cart) SessionUtil.getInstance().getValue(req, CART_USER);

		List<CartItem> cartItemList = cartItemService.findAllByCart(cart.getId());
		int currentIndex = ordersService.currentIndex();
		System.out.print(currentIndex);

		for (CartItem cartItem : cartItemList) {
			OrdersItem ordersItem = new OrdersItem();
			ordersItem.setOrdersId(currentIndex);
			ordersItem.setProductId(cartItem.getProductId());
			ordersItem.setCount(cartItem.getCount());
			Product product = productService.findOneById(cartItem.getProductId());
			productService.updateSold(product.getId(), product.getSold() + cartItem.getCount());
			ordersItemService.insert(ordersItem);
			cartItemService.delete(cartItem.getId());
		}

		cartService.delete(cart.getId());
		userService.updateWallet(user.getId(),
				user.geteWallet() - ordersService.findById(currentIndex).getAmountFromUser());
	}

	protected void changeSessionCart(HttpServletRequest req, HttpServletResponse resp)
			throws ServletException, IOException {
		User user = (User) SessionUtil.getInstance().getValue(req, USER_MODEL);
		User newuser = userService.findById(user.getId());
		List<Cart> carts = cartService.findByUserId(user.getId());
		int countOfCarts = carts.stream().mapToInt(o1 -> o1.getCartItems().stream().mapToInt(o2 -> o2.getCount()).sum())
				.sum();
		SessionUtil.getInstance().putValue(req, CART_HEADER, carts);
		SessionUtil.getInstance().putValue(req, COUNT_CART_HEADER, countOfCarts);
		SessionUtil.getInstance().putValue(req, USER_MODEL, newuser);
	}
	
	protected void insertTransaction(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		req.setCharacterEncoding("UTF-8");
		resp.setCharacterEncoding("UTF-8");

		Cart cart = (Cart) SessionUtil.getInstance().getValue(req, CART_USER);
		User user = (User) SessionUtil.getInstance().getValue(req, USER_MODEL);
		Store store = cart.getStore();
		
		int deliveryId = Integer.parseInt(req.getParameter("deliveryId"));
		
		Double deliveryPrice = deliveryService.findById(deliveryId).getPrice();
		Double amountFromUser = cart.getCartItems().stream().mapToDouble(o1 -> o1.getProduct().getPromotionalPrice())
				.sum() + deliveryPrice;
		Double amountToStore = amountFromUser - 0.025 * amountFromUser;
		
		Transaction transaction = new Transaction();
		transaction.setUserId(user.getId());
		transaction.setStoreId(store.getId());
		transaction.setUp(true);
		transaction.setAmount(amountToStore);
		transactionService.insert(transaction);
		
		storeService.updateWallet(store.getId(), store.geteWallet()+amountToStore);
		
	}
}
