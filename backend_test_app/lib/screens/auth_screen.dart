import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../state/session.dart';
import '../theme.dart';
import '../utils.dart';
import '../widgets/common.dart';

class AuthScreen extends StatefulWidget {
  const AuthScreen({super.key});

  @override
  State<AuthScreen> createState() => _AuthScreenState();
}

class _AuthScreenState extends State<AuthScreen> {
  final _form = GlobalKey<FormState>();
  final _name = TextEditingController();
  final _email = TextEditingController();
  final _password = TextEditingController();
  bool _register = false;
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    for (final c in [_name, _email, _password]) {
      c.dispose();
    }
    super.dispose();
  }

  Future<void> _submit() async {
    if (!_form.currentState!.validate()) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    final session = context.read<Session>();
    try {
      _register
          ? await session.register(_name.text.trim(), _email.text.trim(), _password.text)
          : await session.signIn(_name.text.trim(), _password.text);
      // On success the session flips to signed-in and this screen is replaced.
    } catch (e) {
      if (mounted) {
        setState(() {
          _busy = false;
          _error = errorMessage(e);
        });
      }
    }
  }

  Future<void> _editServer() async {
    final session = context.read<Session>();
    final url =
        await showTextPrompt(context, title: 'API server', label: 'Base URL', initial: session.api.baseUrl);
    if (url != null && url.isNotEmpty) await session.setBaseUrl(url);
  }

  @override
  Widget build(BuildContext context) {
    final session = context.watch<Session>();
    final notice = _error ?? session.notice;

    return Scaffold(
      backgroundColor: Brand.green,
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(24),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 420),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const Text('Little Lemon',
                      textAlign: TextAlign.center,
                      style: TextStyle(color: Brand.yellow, fontSize: 46, fontWeight: FontWeight.w800)),
                  const Text('Chicago',
                      textAlign: TextAlign.center, style: TextStyle(color: Colors.white, fontSize: 22)),
                  const SizedBox(height: 32),
                  Card(
                    child: Padding(
                      padding: const EdgeInsets.all(20),
                      child: Form(
                        key: _form,
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.stretch,
                          children: [
                            SegmentedButton<bool>(
                              showSelectedIcon: false,
                              segments: const [
                                ButtonSegment(value: false, label: Text('Sign in')),
                                ButtonSegment(value: true, label: Text('Create account')),
                              ],
                              selected: {_register},
                              onSelectionChanged: (s) => setState(() {
                                _register = s.first;
                                _error = null;
                              }),
                            ),
                            const SizedBox(height: 20),
                            TextFormField(
                              controller: _name,
                              textInputAction: TextInputAction.next,
                              decoration: const InputDecoration(
                                  labelText: 'Username', prefixIcon: Icon(Icons.person_outline)),
                              validator: (v) => v!.trim().isEmpty ? 'Enter your username' : null,
                            ),
                            if (_register) ...[
                              const SizedBox(height: 12),
                              TextFormField(
                                controller: _email,
                                keyboardType: TextInputType.emailAddress,
                                textInputAction: TextInputAction.next,
                                decoration: const InputDecoration(
                                    labelText: 'Email', prefixIcon: Icon(Icons.mail_outline)),
                                validator: (v) => v!.contains('@') ? null : 'Enter a valid email',
                              ),
                            ],
                            const SizedBox(height: 12),
                            TextFormField(
                              controller: _password,
                              obscureText: true,
                              onFieldSubmitted: (_) => _submit(),
                              decoration: const InputDecoration(
                                  labelText: 'Password', prefixIcon: Icon(Icons.lock_outline)),
                              validator: (v) => v!.length < (_register ? 6 : 1)
                                  ? (_register ? 'Use at least 6 characters' : 'Enter your password')
                                  : null,
                            ),
                            if (notice != null) ...[
                              const SizedBox(height: 12),
                              Text(notice, style: TextStyle(color: Theme.of(context).colorScheme.error)),
                            ],
                            const SizedBox(height: 20),
                            FilledButton(
                              onPressed: _busy ? null : _submit,
                              child: _busy
                                  ? const SizedBox.square(
                                      dimension: 22, child: CircularProgressIndicator(strokeWidth: 2.5))
                                  : Text(_register ? 'Create account' : 'Sign in'),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(height: 12),
                  TextButton.icon(
                    onPressed: _editServer,
                    style: TextButton.styleFrom(foregroundColor: Colors.white70),
                    icon: const Icon(Icons.dns_outlined, size: 18),
                    label: Text(session.api.baseUrl),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
