import 'dart:async';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:intl/intl.dart';

import 'api/api_client.dart';

final _money = NumberFormat.simpleCurrency(name: 'USD');
String money(num value) => _money.format(value);

String errorMessage(Object error) => switch (error) {
      ApiException(:final message) => message,
      TimeoutException() => 'The server is taking too long to respond.',
      http.ClientException() => "Can't reach the server. Is the API running?",
      _ => 'Something went wrong: $error',
    };

void showSnack(BuildContext context, String message) =>
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(message)));

void showError(BuildContext context, Object error) => showSnack(context, errorMessage(error));
