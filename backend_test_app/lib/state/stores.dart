import 'package:flutter/foundation.dart' show ChangeNotifier;

import '../api/api_client.dart';
import '../api/models.dart';

/// Ignores notifications after dispose, since a load can finish after the user signs out.
mixin _SafeNotifier on ChangeNotifier {
  bool _disposed = false;

  @override
  void dispose() {
    _disposed = true;
    super.dispose();
  }

  @override
  void notifyListeners() {
    if (!_disposed) super.notifyListeners();
  }
}

class MenuStore extends ChangeNotifier with _SafeNotifier {
  MenuStore(this.api);

  final ApiClient api;
  List<MenuItem> items = const [];
  List<Category> categories = const [];
  bool loading = false;
  Object? error;

  Future<void> load() async {
    loading = true;
    notifyListeners();
    try {
      final [rawItems, rawCategories] = await Future.wait([
        api.get('/api/menu-items?perpage=100'),
        api.get('/api/categories'),
      ]);
      items = [for (final j in rawItems as List? ?? const []) MenuItem.fromJson(j)];
      categories = [for (final j in rawCategories as List? ?? const []) Category.fromJson(j)];
      error = null;
    } catch (e) {
      error = e;
    }
    loading = false;
    notifyListeners();
  }

  Future<void> addCategory(String title) async {
    await api.post('/api/assign-category', json: {'title': title});
    await load();
  }

  Future<void> addItem({
    required String title,
    required double price,
    required String categoryId,
    bool featured = false,
  }) async {
    await api.post('/api/menu-items',
        json: {'title': title, 'price': price, 'category': categoryId, 'featured': featured});
    await load();
  }

  Future<void> deleteItem(MenuItem item) async {
    await api.delete('/api/menu-items/${item.id}');
    await load();
  }
}

class CartStore extends ChangeNotifier with _SafeNotifier {
  CartStore(this.api);

  final ApiClient api;
  List<CartLine> lines = const [];
  bool loading = false;
  Object? error;

  int get count => lines.fold(0, (n, l) => n + l.quantity);
  double get total => lines.fold(0.0, (sum, l) => sum + l.price);

  Future<void> load() async {
    loading = true;
    notifyListeners();
    try {
      final rows = await api.get('/api/cart/menu-items') as List? ?? const [];
      final merged = <String, CartLine>{};
      for (final row in rows) {
        final line = CartLine.fromJson(row);
        merged.update(line.title, (existing) => existing + line, ifAbsent: () => line);
      }
      lines = merged.values.toList();
      error = null;
    } catch (e) {
      error = e;
    }
    loading = false;
    notifyListeners();
  }

  Future<void> add(MenuItem item, int quantity) async {
    await api.post('/api/cart/menu-items', form: {'menuitem': item.title, 'quantity': '$quantity'});
    await load();
  }

  Future<void> clear() async {
    await api.delete('/api/cart/menu-items');
    lines = const [];
    notifyListeners();
  }

  Future<void> placeOrder() async {
    await api.post('/api/orders');
    lines = const [];
    notifyListeners();
  }
}
