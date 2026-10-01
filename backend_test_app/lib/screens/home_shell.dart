import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../state/session.dart';
import '../state/stores.dart';
import 'cart_screen.dart';
import 'menu_screen.dart';
import 'orders_screen.dart';
import 'profile_screen.dart';

/// Signed-in app: bottom navigation over menu, cart, orders and profile.
/// The stores live here so they are recreated for each sign-in.
class HomeShell extends StatefulWidget {
  const HomeShell({super.key});

  @override
  State<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<HomeShell> {
  int _tab = 0;

  void _goTo(int tab) {
    // A snackbar from the previous tab would float over this tab's bottom panel (e.g. checkout).
    ScaffoldMessenger.of(context).hideCurrentSnackBar();
    setState(() => _tab = tab);
  }

  @override
  Widget build(BuildContext context) {
    final api = context.read<Session>().api;
    return MultiProvider(
      providers: [
        ChangeNotifierProvider(create: (_) => MenuStore(api)..load()),
        ChangeNotifierProvider(create: (_) => CartStore(api)..load()),
      ],
      child: Builder(builder: (context) {
        final cartCount = context.select<CartStore, int>((c) => c.count);
        return Scaffold(
          body: switch (_tab) {
            0 => const MenuScreen(),
            1 => CartScreen(onBrowse: () => _goTo(0), onOrdered: () => _goTo(2)),
            2 => const OrdersScreen(),
            _ => const ProfileScreen(),
          },
          bottomNavigationBar: NavigationBar(
            selectedIndex: _tab,
            onDestinationSelected: _goTo,
            destinations: [
              const NavigationDestination(
                  icon: Icon(Icons.restaurant_menu_outlined),
                  selectedIcon: Icon(Icons.restaurant_menu),
                  label: 'Menu'),
              NavigationDestination(
                  icon: Badge.count(
                      count: cartCount,
                      isLabelVisible: cartCount > 0,
                      child: const Icon(Icons.shopping_bag_outlined)),
                  selectedIcon: Badge.count(
                      count: cartCount, isLabelVisible: cartCount > 0, child: const Icon(Icons.shopping_bag)),
                  label: 'Cart'),
              const NavigationDestination(
                  icon: Icon(Icons.receipt_long_outlined),
                  selectedIcon: Icon(Icons.receipt_long),
                  label: 'Orders'),
              const NavigationDestination(
                  icon: Icon(Icons.person_outline), selectedIcon: Icon(Icons.person), label: 'Profile'),
            ],
          ),
        );
      }),
    );
  }
}
