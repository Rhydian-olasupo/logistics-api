class Category {
  const Category(this.id, this.title);

  final String id;
  final String title;

  factory Category.fromJson(Map<String, dynamic> j) => Category(j['id'], j['title'] ?? '');
}

class MenuItem {
  const MenuItem({
    required this.id,
    required this.title,
    required this.price,
    this.featured = false,
    this.category,
  });

  final String id;
  final String title;
  final double price;
  final bool featured;
  final Category? category;

  factory MenuItem.fromJson(Map<String, dynamic> j) => MenuItem(
        id: j['id'],
        title: j['title'] ?? '',
        price: (j['price'] as num? ?? 0).toDouble(),
        featured: j['featured'] ?? false,
        category: j['category'] is Map<String, dynamic> ? Category.fromJson(j['category']) : null,
      );
}

/// A dish in the cart. The API stores one row per "add", so rows for the same dish get merged with [+].
class CartLine {
  const CartLine({
    required this.title,
    required this.quantity,
    required this.unitPrice,
    required this.price,
  });

  final String title;
  final int quantity;
  final double unitPrice;
  final double price;

  factory CartLine.fromJson(Map<String, dynamic> j) => CartLine(
        title: j['menuitem'] ?? '',
        quantity: (j['quantity'] as num).toInt(),
        unitPrice: (j['unit_price'] as num).toDouble(),
        price: (j['price'] as num).toDouble(),
      );

  CartLine operator +(CartLine other) => CartLine(
        title: title,
        quantity: quantity + other.quantity,
        unitPrice: unitPrice,
        price: price + other.price,
      );
}

class Order {
  const Order({required this.id, required this.total, required this.date, required this.delivered});

  final String id;
  final double total;
  final DateTime date;
  final bool delivered;

  String get number => id.substring(id.length - 6).toUpperCase();

  factory Order.fromJson(Map<String, dynamic> j) => Order(
        id: j['id'],
        total: (j['total'] as num).toDouble(),
        date: DateTime.parse(j['date']).toLocal(),
        delivered: j['status'] ?? false,
      );
}
