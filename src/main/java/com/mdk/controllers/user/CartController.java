package com.mdk.controllers.user;

import java.io.IOException;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.mdk.models.Cart;
import com.mdk.models.CartItem;
import com.mdk.models.Delivery;
import com.mdk.models.Product;
import com.mdk.models.User;
import com.mdk.services.ICartItemService;
import com.mdk.services.ICartService;
import com.mdk.services.IDeliveryService;
import com.mdk.services.IProductService;
import com.mdk.services.IStoreService;
import com.mdk.services.IUserService;
import com.mdk.services.impl.CartItemService;
import com.mdk.services.impl.CartService;
import com.mdk.services.impl.DeliveryService;
import com.mdk.services.impl.ProductService;
import com.mdk.services.impl.StoreService;
import com.mdk.services.impl.UserService;
import com.mdk.utils.SessionUtil;

import static com.mdk.utils.AppConstant.*;

@WebServlet(urlPatterns = { "/web/cart", "/web/cart/delivery", "/web/cart/item/create", "/web/cart/item/delete" })
public class CartController extends HttpServlet {
	private static final long serialVersionUID = 1L;
	ICartService cartService = new CartService();
	IStoreService storeService = new StoreService();
	ICartItemService cartItemService = new CartItemService();
	IProductService productService = new ProductService();
	IDeliveryService deliveryService = new DeliveryService();
	IUserService userService = new UserService();

	@Override
	protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String url = req.getRequestURL().toString();

		if (url.contains("/web/cart/delivery")) {
			/*
			 * User user = (User) SessionUtil.getInstance().getValue(req, "USER");
			 * List<Cart> listCart = cartService.findByUserId(user.getId()); List<Store>
			 * listStore = new ArrayList<Store>(); List<CartItem> listCartItem = new
			 * ArrayList<CartItem>(); List<Product> listProduct = new ArrayList<Product>();
			 * for (Cart cart : listCart) {
			 * listStore.add(storeService.findById(cart.getStoreId())); for (CartItem
			 * cartItem : cartItemService.findAllByCart(cart.getId())) {
			 * listCartItem.add(cartItem); Product product =
			 * productService.findOneById(cartItem.getProductId()); if
			 * (!listProduct.stream().filter(o -> o.getId() ==
			 * product.getId()).findFirst().isPresent()) listProduct.add(product); } }
			 * 
			 * req.setAttribute("listCart", listCart); req.setAttribute("listStore",
			 * listStore); req.setAttribute("listCartItem", listCartItem);
			 * req.setAttribute("listProduct", listProduct); req.setAttribute("user", user);
			 * req.getRequestDispatcher("/views/web/addressdelivery.jsp").forward(req,
			 * resp);
			 */
		} else if (url.contains("/web/cart")) {
			baseInfo(req, resp);
			User user = (User) SessionUtil.getInstance().getValue(req, USER_MODEL);
			List<Cart> listCart = cartService.findByUserId(user.getId());
			req.setAttribute("listCart", listCart);
			req.getRequestDispatcher("/views/web/checkout.jsp").forward(req, resp);
		}
	}

	@Override
	protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		String url = req.getRequestURL().toString();

		if (url.contains("/web/cart/delivery")) {
			baseInfo(req, resp);
			Cart cart = cartService.findById(Integer.parseInt(req.getParameter("cart")));
			List<Delivery> listDelivery = deliveryService.findAllActive();

			SessionUtil.getInstance().putValue(req, CART_USER, cart);

			req.setAttribute("cart", cart);
			req.setAttribute("listDelivery", listDelivery);
			req.getRequestDispatcher("/views/web/addressdelivery.jsp").forward(req, resp);
		} else if (url.contains("/web/cart/item/create")) {
			insertItem(req, resp);
			changeSessionCart(req, resp);
			resp.sendRedirect(req.getHeader("referer"));
		} else if (url.contains("/web/cart/item/delete")) {
			deleteItem(req, resp);
			changeSessionCart(req, resp);
			resp.sendRedirect(req.getContextPath() + "/web");
		}
	}

	protected void insertItem(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

		Product product = productService.findOneById(Integer.parseInt(req.getParameter("id")));
		User user = (User) SessionUtil.getInstance().getValue(req, USER_MODEL);
		Cart cart = cartService.findByUserAndStore(user.getId(), product.getStoreId());
		if (cart == null) {
			cart = new Cart();
			cart.setUserId(user.getId());
			cart.setStoreId(product.getStoreId());
			cartService.insert(cart);
			cart = cartService.findByUserAndStore(user.getId(), product.getStoreId());
		}

		int count = 0;

		if (req.getParameter("count") != null)
			count = Integer.parseInt(req.getParameter("count"));
		else if (product.getQuantity() == 0)
			count = 0;
		else
			count = 1;

		System.out.print(count);

		CartItem cartItem = new CartItem();
		CartItem cartItemTemp = cartItemService.findByCartAndProduct(cart.getId(),
				Integer.parseInt(req.getParameter("id")));

		if (cartItemTemp == null) {
			cartItem.setCartId(cart.getId());
			cartItem.setProductId(Integer.parseInt(req.getParameter("id")));
			cartItem.setCount(count);
			cartItemService.insert(cartItem);
		} else {
			cartItemTemp.setCount(count + cartItemTemp.getCount());
			cartItemService.update(cartItemTemp);
		}

		product.setQuantity(product.getQuantity() - count);
		productService.update(product);

	}

	protected void deleteItem(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
		CartItem cartItem = cartItemService.findOneById(Integer.parseInt(req.getParameter("id")));
		cartItemService.delete(cartItem.getId());
		cartItem.getProduct().setQuantity(cartItem.getProduct().getQuantity() + cartItem.getCount());
		productService.update(cartItem.getProduct());
	}

	protected void baseInfo(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

		User user = (User) SessionUtil.getInstance().getValue(req, USER_MODEL);
		req.setAttribute("user", user);
		List<Cart> carts = cartService.findByUserId(user.getId());
		int countOfCarts = carts.stream().mapToInt(o1 -> o1.getCartItems().stream().mapToInt(o2 -> o2.getCount()).sum())
				.sum();
		req.setAttribute("carts", carts);
		req.setAttribute("countOfCarts", countOfCarts);
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

}
