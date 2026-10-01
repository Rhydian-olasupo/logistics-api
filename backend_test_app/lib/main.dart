import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import 'api/api_client.dart';
import 'screens/auth_screen.dart';
import 'screens/home_shell.dart';
import 'state/session.dart';
import 'theme.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  final session = Session(ApiClient(defaultBaseUrl));
  await session.restore();
  runApp(ChangeNotifierProvider.value(value: session, child: const LittleLemonApp()));
}

class LittleLemonApp extends StatelessWidget {
  const LittleLemonApp({super.key});

  @override
  Widget build(BuildContext context) {
    final signedIn = context.select<Session, bool>((s) => s.signedIn);
    return MaterialApp(
      title: 'Little Lemon',
      debugShowCheckedModeBanner: false,
      theme: buildTheme(),
      home: signedIn ? const HomeShell() : const AuthScreen(),
    );
  }
}
