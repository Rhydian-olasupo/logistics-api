import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../state/session.dart';
import '../theme.dart';
import '../widgets/common.dart';
import 'manage_menu.dart';

class ProfileScreen extends StatefulWidget {
  const ProfileScreen({super.key});

  @override
  State<ProfileScreen> createState() => _ProfileScreenState();
}

class _ProfileScreenState extends State<ProfileScreen> {
  late final Future<dynamic> _me = context.read<Session>().api.get('/api/user/me/');

  @override
  Widget build(BuildContext context) {
    final session = context.watch<Session>();
    final name = session.username ?? '';

    return Scaffold(
      appBar: AppBar(title: const Text('Profile')),
      body: RefreshIndicator(
        onRefresh: session.loadRole,
        child: ListView(
          padding: const EdgeInsets.all(20),
          children: [
            Card(
              child: Padding(
                padding: const EdgeInsets.all(20),
                child: Row(
                  children: [
                    CircleAvatar(
                      radius: 30,
                      backgroundColor: Brand.yellow,
                      child: Text(
                        name.isEmpty ? '?' : name[0].toUpperCase(),
                        style: const TextStyle(fontSize: 24, fontWeight: FontWeight.w800, color: Brand.ink),
                      ),
                    ),
                    const SizedBox(width: 16),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(name, style: const TextStyle(fontSize: 20, fontWeight: FontWeight.w800)),
                          FutureBuilder(
                            future: _me,
                            builder: (_, snap) => Text(
                              snap.data?['email'] ?? '',
                              style: const TextStyle(color: Colors.black54),
                            ),
                          ),
                        ],
                      ),
                    ),
                    Chip(
                      label: Text(session.isManager ? 'Manager' : 'Customer'),
                      backgroundColor: session.isManager ? Brand.green : Brand.peach,
                      labelStyle: TextStyle(
                        fontWeight: FontWeight.w700,
                        color: session.isManager ? Colors.white : Brand.ink,
                      ),
                    ),
                  ],
                ),
              ),
            ),
            if (session.isManager) ...[
              const SectionLabel('Manage menu'),
              Card(
                clipBehavior: Clip.antiAlias,
                child: Column(
                  children: [
                    ListTile(
                      leading: const Icon(Icons.add_circle_outline),
                      title: const Text('Add a dish'),
                      onTap: () => showAddDishSheet(context),
                    ),
                    const Divider(height: 1),
                    ListTile(
                      leading: const Icon(Icons.category_outlined),
                      title: const Text('Add a category'),
                      onTap: () => addCategory(context),
                    ),
                    const Divider(height: 1),
                    const ListTile(
                      leading: Icon(Icons.touch_app_outlined),
                      title: Text('Remove a dish'),
                      subtitle: Text('Long-press it on the menu'),
                    ),
                  ],
                ),
              ),
            ],
            const SectionLabel('App'),
            Card(
              clipBehavior: Clip.antiAlias,
              child: Column(
                children: [
                  ListTile(
                    leading: const Icon(Icons.dns_outlined),
                    title: const Text('Server'),
                    subtitle: Text(session.api.baseUrl),
                  ),
                  const Divider(height: 1),
                  ListTile(
                    leading: const Icon(Icons.logout, color: Colors.redAccent),
                    title: const Text('Sign out', style: TextStyle(color: Colors.redAccent)),
                    onTap: session.signOut,
                  ),
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }
}
