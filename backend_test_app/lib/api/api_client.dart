import 'dart:convert';

import 'package:flutter/foundation.dart';
import 'package:http/http.dart' as http;

/// Android emulators reach the host machine at 10.0.2.2; everything else uses localhost.
/// Override with: flutter run --dart-define=API_URL=http://192.168.1.10:8000
String get defaultBaseUrl {
  const fromEnv = String.fromEnvironment('API_URL');
  if (fromEnv.isNotEmpty) return fromEnv;
  final android = !kIsWeb && defaultTargetPlatform == TargetPlatform.android;
  return android ? 'http://10.0.2.2:8000' : 'http://localhost:8000';
}

class ApiException implements Exception {
  ApiException(this.statusCode, this.message);

  final int statusCode;
  final String message;

  @override
  String toString() => message;
}

/// Thin HTTP client for the Little Lemon API. Throws [ApiException] on 4xx/5xx.
class ApiClient {
  ApiClient(this.baseUrl);

  String baseUrl;
  String? token;

  /// Called when the API rejects the token (it answers 403 for expired or invalid JWTs).
  VoidCallback? onTokenRejected;

  Future<dynamic> get(String path) => _send('GET', path);

  Future<dynamic> post(String path, {Object? json, Map<String, String>? form}) =>
      _send('POST', path, json: json, form: form);

  Future<dynamic> delete(String path) => _send('DELETE', path);

  Future<dynamic> _send(String method, String path, {Object? json, Map<String, String>? form}) async {
    final req = http.Request(method, Uri.parse('$baseUrl$path'));
    if (token != null) req.headers['token'] = token!;
    if (json != null) {
      req.headers['Content-Type'] = 'application/json';
      req.body = jsonEncode(json);
    } else if (form != null) {
      req.bodyFields = form; // the login and cart endpoints expect form data
    }

    final res = await http.Response.fromStream(await req.send().timeout(const Duration(seconds: 10)));

    if (res.statusCode == 403 && token != null) onTokenRejected?.call();
    if (res.statusCode >= 400) {
      // The API returns plain-text errors, which are already user-readable.
      final body = res.body.trim();
      throw ApiException(res.statusCode, body.isEmpty ? 'Request failed (${res.statusCode})' : body);
    }
    if (res.body.isEmpty) return null;
    try {
      return jsonDecode(res.body);
    } on FormatException {
      return res.body;
    }
  }
}
