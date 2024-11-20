import 'package:flutter/material.dart';
import 'dart:convert';
import 'package:http/http.dart' as http;

void main() {
  runApp(const CreateUserApp());
}


class CreateUserApp extends StatelessWidget {
  const CreateUserApp({super.key});

  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      home: CreateUserScreen(),
    );
  }
}

class CreateUserScreen extends StatefulWidget {
  const CreateUserScreen({super.key});

  @override
  // ignore: library_private_types_in_public_api
  _CreateUserScreenState createState() => _CreateUserScreenState();

}

class _CreateUserScreenState extends State<CreateUserScreen> {
  final _formKey = GlobalKey<FormState>();
  String _name = '';
  String _email = '';
  String _password = '';
  bool _isLoading = false;
  String _responseMessage = '';

  // Replace with your backend endpoint URL
  final String _endpointUrl = 'https://8e32-102-89-44-246.ngrok-free.app/api/users';

  Future<void> _createUser() async {
    setState(() {
      _isLoading = true;
      _responseMessage = '';
    });

    try {
      final response = await http.post(
        Uri.parse(_endpointUrl),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'name': _name,
          'email': _email,
          'password': _password,
        }),
      );

      if (response.statusCode == 201) {
        setState(() {
          _responseMessage = 'User created successfully!';
        });
      } else {
        final errorResponse = jsonDecode(response.body);
        setState(() {
          _responseMessage =
              'Error: ${errorResponse['message'] ?? 'Unknown error occurred'}';
        });
      }
    } catch (e) {
      setState(() {
        _responseMessage = 'Error: $e';
      });
    } finally {
      setState(() {
        _isLoading = false;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Create User'),
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Form(
          key: _formKey,
          child: Column(
            children: [
              TextFormField(
                decoration: const InputDecoration(labelText: 'Name'),
                validator: (value) =>
                    value == null || value.isEmpty ? 'Name is required' : null,
                onSaved: (value) => _name = value ?? '',
              ),
              TextFormField(
                decoration: const InputDecoration(labelText: 'Email'),
                keyboardType: TextInputType.emailAddress,
                validator: (value) => value == null || !value.contains('@')
                    ? 'Enter a valid email'
                    : null,
                onSaved: (value) => _email = value ?? '',
              ),
              TextFormField(
                decoration: const InputDecoration(labelText: 'Password'),
                obscureText: true,
                validator: (value) =>
                    value == null || value.isEmpty ? 'Password is required' : null,
                onSaved: (value) => _password = value ?? '',
              ),
              const SizedBox(height: 16.0),
              if (_isLoading)
                const CircularProgressIndicator()
              else
                ElevatedButton(
                  onPressed: () {
                    if (_formKey.currentState?.validate() ?? false) {
                      _formKey.currentState?.save();
                      _createUser();
                    }
                  },
                  child: const Text('Create User'),
                ),
              const SizedBox(height: 16.0),
              if (_responseMessage.isNotEmpty)
                Text(
                  _responseMessage,
                  style: TextStyle(color: _responseMessage.startsWith('Error')
                      ? Colors.red
                      : Colors.green),
                ),
            ],
          ),
        ),
      ),
    );
  }
}

