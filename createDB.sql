use ecommerce_v2;
create table address
(
    id int auto_increment,
    name       varchar(200),
    constraint pk_address primary key (id)
);
create table user
(
    id int      auto_increment,
    sex 			varchar(32) default 'Đang cập nhật',  
    firstname       varchar(32) not null,
    lastname        varchar(32) not null,
    id_card         varchar(9) unique,
    email           varchar(50) unique not null,
    phone           varchar(12) unique,
    isEmailActive   boolean   default false,
    isPhoneActive   boolean   default false,
    password 		varchar(50) not null,
    role            varchar(50) not null default 'USER',
    avatar          varchar(100),
    eWallet        double  default 0,
    createdAt       timestamp default now(),
    updatedAt        timestamp default now() on update now(),
    constraint pk_user primary key (id)
);
create table user_address
(
    addressId int,
    userId    int,
    constraint pk_user_address primary key (addressId, userId),
    constraint fk_user foreign key (userId) references user (id),
    constraint fk_address foreign key (addressId) references address (id)
);
create table store
(
    id 			int   auto_increment,
    name         varchar(100) not null unique,
    bio          varchar(255) not null,
    ownerId      int not null,
    isOpen       boolean   default true,
    avatar       varchar(100),
    rating       int       default 3,
    eWallet     double   default 0,
    createdAt    timestamp default now(),
    updatedAt     timestamp default now() on update now(),
    constraint pk_store primary key (id),
    constraint fk_owner foreign key (ownerId) references user (id),
    constraint check_store_rating check (0 <= rating <= 5)
);

create table image_store
(
	id int auto_increment,
    name varchar(255),
    storeId int,
    constraint pk_image_store primary key(id),
    constraint fk_image_store foreign key(storeId) references store(id)
);

create table category
(
    id int auto_increment,
    name       varchar(32) not null unique,
    isDeleted  boolean   default false,
    createdAt  timestamp default now(),
    updatedAt   timestamp default now() on update now(),
    constraint pk_category primary key (id)
);

create table product
(
    id int       auto_increment,
    name             varchar(100) not null unique,
    description      varchar(1000) not null,
    price            double not null,
    promotionalPrice double not null,
    quantity         int     not null,
    sold             int     not null default 0,
    isActive         boolean default true,
    categoryId       int  not null,
    storeId          int  not null,
    rating           int     default 3,
    createdAt        timestamp default now(),
    updatedAt        timestamp default now() on update now(),

    constraint pk_product primary key (id),
    constraint fk_product_store foreign key (storeId) references store (id),
    constraint fk_product_category foreign key (categoryId) references category (id),
    constraint check_product_rating check (0 <= rating <= 5),
    constraint check_product_sold check (sold >= 0),
    constraint check_product_quantity check (quantity >= 0),
    constraint check_product_promotionalPrice check (promotionalPrice > 0),
    constraint check_product_price check (price > 0),
    constraint check_product_name check (length(name) <= 100)
);

create table image_product
(
	id int auto_increment,
    name varchar(255),
    productId int,
    constraint pk_image_product primary key(id),
    constraint fk_image_product foreign key(productId) references product(id)
);

create table delivery
(
    id int  auto_increment,
    name        varchar(100) not null unique,
    description varchar(1000) not null,
    price       double not null,
    isDeleted   boolean default false,
    createdAt   timestamp default now(),
    updatedAt   timestamp default now() on update now(),

    constraint pk_delivery primary key (id),
    constraint check_delivery_price check (price > 0),
    constraint check_delivery_name check (length(name) <= 100)
);


create table userfollowstore
(
    id int auto_increment,
    userId     int not null,
    storeId    int not null,
    createdAt  timestamp null,
    updatedAt  timestamp null,

    constraint pk_userfollowstore primary key (id),
    constraint fk_userfollowstore_store foreign key (storeId) references store (id),
    constraint fk_userfollowstore_user foreign key (userId) references user (id)
);

create table userfollowproduct
(
    id int auto_increment,
    userId     int not null,
    productId  int not null,
    createdAt  timestamp null,
    updatedAt  timestamp null,

    constraint pk_userfollowproduct primary key (id),
    constraint fk_userfollowproduct_product foreign key (productId) references product (id),
    constraint fk_userfollowproduct_user foreign key (userId) references user (id)
);

create table orders
(
    id int      auto_increment,
    userId          int  not null,
    storeId         int  not null,
    deliveryId      int  not null,
    address         varchar(255) not null,
    phone           varchar(10) not null,
    status          varchar(50) default 'not processed',
    amountFromUser  double not null,
    amountToStore   double not null,
    amountToGD      double not null,
    createdAt       timestamp default now(),
    updatedAt       timestamp default now() on update now(),

    constraint pk_orders primary key (id),
    constraint fk_orders_user foreign key (userId) references user (id),
    constraint fk_orders_store foreign key (storeId) references store (id),
    constraint fk_oder_delivery foreign key (deliveryId) references delivery (id),
    constraint check_orders_amountFromUser check (amountFromUser >= 0),
    constraint check_orders_amountToStore check (amountToStore >= 0),
    constraint check_orders_amountToGD check (amountToGD >= 0)
);

create table review
(
    id int        not null auto_increment,
    userId    int  not null,
    productId int  not null,
    storeId   int  not null,
    ordersId  int  not null,
    content   varchar(1001) not null,
    stars     int not null,
    createdAt timestamp default now(),
    updatedAt timestamp default now() on update now(),

    constraint pk_review primary key (id),
    constraint fk_review_user foreign key (userId) references user (id),
    constraint fk_review_product foreign key (productId) references product (id),
    constraint fk_review_store foreign key (storeId) references store (id),
    constraint fk_review_orders foreign key (ordersId) references orders (id),
    constraint check_review_content check (length(content) <= 1000),
    constraint check_review_stars check (0 <= stars <= 5)
);

create table ordersItem
(
    id int        not null auto_increment,
    ordersId  int  not null,
    productId int  not null,
    count     int not null,
    createdAt timestamp default now(),
    updatedAt timestamp default now() on update now(),

    constraint pk_ordersItem primary key (id),
    constraint fk_ordersItem_orders foreign key (ordersId) references orders (id),
    constraint fk_ordersItem_product foreign key (productId) references product (id),
    constraint check_ordersItem_count check (count >= 1)
);

create table cart
(
    id int       not null auto_increment,
    userId    int not null,
    storeId   int not null,
    createdAt timestamp default now(),
    updatedAt timestamp default now() on update now(),

    constraint pk_cart primary key (id),
    constraint fk_cart_user foreign key (userId) references user (id),
    constraint fk_cart_store foreign key (storeId) references store (id)
);

create table cartItem
(
    id int       not null auto_increment,
    cartId    int not null,
    productId int not null,
    count     int not null,
    createdAt timestamp default now(),
    updatedAt timestamp default now() on update now(),

    constraint pk_cartItem primary key (id),
    constraint fk_cartItem_card foreign key (cartId) references cart (id),
    constraint fk_cartItem_product foreign key (productId) references product (id),
    constraint check_cartItem_count check (count >= 1)
);

create table transaction
(
    id int        not null auto_increment,
    userId    int  not null,
    storeId   int  not null,
    isUp      boolean not null,
    amount    double not null,
    createdAt timestamp default now(),
    updatedAt timestamp default now() on update now(),

    constraint pk_transaction primary key (id),
    constraint fk_transaction_user foreign key (userId) references user (id),
    constraint fk_transaction_store foreign key (storeId) references store (id)
);

select * from user;
select * from store;
select * from transaction;
select * from orders;

insert into user (firstname, lastname, email, password, role) values ('admin', 'admin', 'admin@admin', '12345', 'ADMIN');
insert into user (sex, firstname, lastname, id_card, email, phone, password) values ('Nam', 'Minh Mẫn', 'Trần', '123456789', 'mantm040702@gmail.com', '0964294799', '1');
insert into user (sex, firstname, lastname, id_card, email, phone, password) values ('Nam', 'Hải Đăng', 'Lê', '223456789', '20110243@student.hcmute.edu.vn', '0964344799', '1');
insert into user (sex, firstname, lastname, id_card, email, phone, password) values ('Nam', 'Phúc Hậu', 'Nguyễn', '323456789', 'phuchau12@gmail.com', '0964694779', '1');
insert into user (sex, firstname, lastname, id_card, email, phone, password) values ('Nữ', 'Thị Kiều Trâm', 'Thái', '423456789', 'kieutram02@gmail.com', '0964294790', '1');
insert into user (sex, firstname, lastname, id_card, email, phone, password) values ('Nữ', 'Quỳnh Thương', 'Củng', '523456789', 'quynhthuong16@gmail.com', '0964293499', '1');
insert into user (sex, firstname, lastname, id_card, email, phone, password) values ('Nữ', 'Thị Mỹ Lệ', 'Nguyễn', '623456789', 'myle98@gmail.com', '0964254799', '1');
insert into user (sex, firstname, lastname, id_card, email, phone, password) values ('Nữ', 'Võ Kim Ngân', 'Nguyễn', '723456789', 'kimngan13@gmail.com', '0964294711', '1');
insert into user (sex, firstname, lastname, id_card, email, phone, password) values ('Nam', 'Minh Trí', 'Ngô', '823456789', 'minhtri89@gmail.com', '0964294713', '1');
insert into user (sex, firstname, lastname, id_card, email, phone, password) values ('Nam', 'Khánh Đạt', 'Đỗ', '923456789', 'khanhdat11@gmail.com', '0966694799', '1');
insert into user (firstname, lastname, id_card, email, phone, password) values ('Thanh Phú', 'Nguyễn', '102345789', 'thanhphu11@gmail.com', '0244294799', '1');
insert into user (firstname, lastname, id_card, email, phone, password) values ('Minh Tâm', 'Lê', '112345689', 'minhtam99@gmail.com', '0244134799', '1');
insert into user (firstname, lastname, id_card, email, phone, password) values ('Minh Hảo', 'Hoàng', '122345789', 'minhhao59@gmail.com', '0247734799', '1');