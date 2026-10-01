import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../api/api_client.dart';

/// Who is signed in, persisted across launches.
class Session extends ChangeNotifier {
  Session(this.api) {
    api.onTokenRejected = () => _clear(expired: true);
  }

  final ApiClient api;
  String? username;
  bool isManager = false;

  /// One-off message for the sign-in screen, e.g. after the token expired.
  String? notice;

  bool get signedIn => api.token != null;

  Future<void> restore() async {
    final prefs = await SharedPreferences.getInstance();
    api.baseUrl = prefs.getString('baseUrl') ?? api.baseUrl;
    api.token = prefs.getString('token');
    username = prefs.getString('username');
    if (signedIn) loadRole();
  }

  Future<void> setBaseUrl(String url) async {
    api.baseUrl = url;
    notifyListeners();
    await (await SharedPreferences.getInstance()).setString('baseUrl', url);
  }

  Future<void> register(String name, String email, String password) async {
    await api.post('/api/users', json: {'name': name, 'email': email, 'password': password});
    await signIn(name, password);
  }

  Future<void> signIn(String name, String password) async {
    final res = await api.post('/token/login/', form: {'name': name, 'password': password});
    api.token = res['token'];
    username = name;
    notice = null;
    notifyListeners();
    loadRole();

    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('token', api.token!);
    await prefs.setString('username', name);
  }

  Future<void> signOut() async {
    try {
      await api.post('/api/logout');
    } catch (_) {} // server-side cleanup is best effort; sign out locally regardless
    await _clear();
  }

  /// The API has no "my role" endpoint, so check whether we're in the manager group.
  Future<void> loadRole() async {
    try {
      final managers = await api.get('/api/groups/manager/users') as List? ?? const [];
      isManager = managers.any((m) => m['name'] == username);
      notifyListeners();
    } catch (_) {} // treat as a customer if the lookup fails
  }

  Future<void> _clear({bool expired = false}) async {
    if (!signedIn) return;
    api.token = null;
    username = null;
    isManager = false;
    notice = expired ? 'Your session expired. Please sign in again.' : null;
    notifyListeners();

    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('token');
    await prefs.remove('username');
  }
}
