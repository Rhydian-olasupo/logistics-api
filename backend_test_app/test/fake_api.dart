import 'package:backend_test_app/api/api_client.dart';

/// In-memory stand-in for the Go API, shaped like its real JSON responses.
class FakeApi extends ApiClient {
  FakeApi() : super('http://fake');

  static const _prices = {
    'Greek Salad': 12.99,
    'Bruschetta': 5.99,
    'Lemon Dessert': 5.0,
    'Grilled Fish': 20.0
  };

  final cart = <Map<String, dynamic>>[];
  final orders = <Map<String, dynamic>>[
    {'id': '6650a1b2c3d4e5f6a7b8c9d0', 'total': 31.98, 'date': '2026-09-28T19:30:00Z', 'status': true},
  ];

  @override
  Future<dynamic> get(String path) async => switch (path.split('?').first) {
        '/api/menu-items' => [
            _item('a1', 'Greek Salad', featured: true, category: _starters),
            _item('a2', 'Bruschetta', featured: true, category: _starters),
            _item('a3', 'Grilled Fish', category: _mains),
            _item('a4', 'Lemon Dessert', category: _desserts),
          ],
        '/api/categories' => [_starters, _mains, _desserts],
        '/api/cart/menu-items' => cart,
        '/api/orders' => orders,
        '/api/groups/manager/users' => [
            {'name': 'chef', 'group': 'Manager'},
          ],
        '/api/user/me/' => {'name': 'chef', 'email': 'chef@littlelemon.com'},
        _ => throw ApiException(404, 'Not found: $path'),
      };

  @override
  Future<dynamic> post(String path, {Object? json, Map<String, String>? form}) async {
    switch (path) {
      case '/token/login/':
        return {'token': 'fake-jwt', 'refresh_token': 'fake-refresh'};
      case '/api/cart/menu-items':
        final qty = int.parse(form!['quantity']!);
        final unit = _prices[form['menuitem']]!;
        cart.add({'menuitem': form['menuitem'], 'quantity': qty, 'unit_price': unit, 'price': unit * qty});
      case '/api/orders':
        final total = cart.fold<double>(0, (t, r) => t + r['price']);
        orders.add({
          'id': '6650a1b2c3d4e5f6a7b8ffff',
          'total': total,
          'date': '2026-10-01T12:00:00Z',
          'status': false
        });
        cart.clear();
    }
    return null;
  }

  @override
  Future<dynamic> delete(String path) async => cart.clear();

  static const _starters = {'id': 'c1', 'title': 'Starters'};
  static const _mains = {'id': 'c2', 'title': 'Mains'};
  static const _desserts = {'id': 'c3', 'title': 'Desserts'};

  static Map<String, dynamic> _item(String id, String title,
          {bool featured = false, required Map<String, String> category}) =>
      {'id': id, 'title': title, 'price': _prices[title], 'featured': featured, 'category': category};
}
