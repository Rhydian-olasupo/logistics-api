import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../api/models.dart';
import '../state/stores.dart';
import '../theme.dart';
import '../utils.dart';
import '../widgets/common.dart';
import '../widgets/food_art.dart';

class CartScreen extends StatelessWidget {
  const CartScreen({super.key, required this.onBrowse, required this.onOrdered});

  final VoidCallback onBrowse;
  final VoidCallback onOrdered;

  Future<void> _confirmClear(BuildContext context) async {
    final cart = context.read<CartStore>();
    final ok = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Clear your order?'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Keep')),
          TextButton(onPressed: () => Navigator.pop(context, true), child: const Text('Clear')),
        ],
      ),
    );
    if (ok != true) return;
    try {
      await cart.clear();
    } catch (e) {
      if (context.mounted) showError(context, e);
    }
  }

  @override
  Widget build(BuildContext context) {
    final cart = context.watch<CartStore>();
    final Widget body;
    if (cart.lines.isNotEmpty) {
      body = RefreshIndicator(
        onRefresh: cart.load,
        child: ListView.separated(
          padding: const EdgeInsets.all(20),
          itemCount: cart.lines.length,
          separatorBuilder: (_, __) => const SizedBox(height: 12),
          itemBuilder: (_, i) => _CartLineCard(cart.lines[i]),
        ),
      );
    } else if (cart.loading) {
      body = const Center(child: CircularProgressIndicator());
    } else if (cart.error != null) {
      body = EmptyState(
        icon: Icons.wifi_off,
        title: "Couldn't load your order",
        message: errorMessage(cart.error!),
        action: TextButton(onPressed: cart.load, child: const Text('Try again')),
      );
    } else {
      body = EmptyState(
        icon: Icons.shopping_bag_outlined,
        title: 'Your bag is empty',
        message: 'Add a dish from the menu to get started.',
        action: FilledButton.tonal(onPressed: onBrowse, child: const Text('Browse the menu')),
      );
    }

    return Scaffold(
      appBar: AppBar(
        title: const Text('Your order'),
        actions: [
          if (cart.lines.isNotEmpty)
            TextButton(onPressed: () => _confirmClear(context), child: const Text('Clear')),
        ],
      ),
      body: body,
      bottomNavigationBar: cart.lines.isEmpty ? null : _CheckoutPanel(onOrdered: onOrdered),
    );
  }
}

class _CartLineCard extends StatelessWidget {
  const _CartLineCard(this.line);

  final CartLine line;

  @override
  Widget build(BuildContext context) => Card(
        child: Padding(
          padding: const EdgeInsets.all(12),
          child: Row(
            children: [
              FoodArt(line.title, height: 60, radius: 12),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(line.title, style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w700)),
                    Text('${line.quantity} × ${money(line.unitPrice)}',
                        style: const TextStyle(color: Colors.black54)),
                  ],
                ),
              ),
              Text(money(line.price), style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w800)),
            ],
          ),
        ),
      );
}

class _CheckoutPanel extends StatefulWidget {
  const _CheckoutPanel({required this.onOrdered});

  final VoidCallback onOrdered;

  @override
  State<_CheckoutPanel> createState() => _CheckoutPanelState();
}

class _CheckoutPanelState extends State<_CheckoutPanel> {
  bool _busy = false;

  Future<void> _placeOrder() async {
    setState(() => _busy = true);
    try {
      await context.read<CartStore>().placeOrder();
      if (!mounted) return;
      final messenger = ScaffoldMessenger.of(context);
      widget.onOrdered(); // switches tabs, which clears any current snackbar
      messenger.showSnackBar(const SnackBar(content: Text("Order placed! We're on it.")));
    } catch (e) {
      if (mounted) {
        setState(() => _busy = false);
        showError(context, e);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final total = context.select<CartStore, double>((c) => c.total);
    return Container(
      decoration: const BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
        boxShadow: [BoxShadow(color: Colors.black12, blurRadius: 16)],
      ),
      padding: const EdgeInsets.fromLTRB(20, 20, 20, 12),
      child: SafeArea(
        top: false,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            _row('Subtotal', money(total)),
            _row('Delivery', 'Free'),
            const Divider(height: 24),
            _row('Total', money(total), bold: true),
            const SizedBox(height: 16),
            FilledButton(
              onPressed: _busy ? null : _placeOrder,
              style: FilledButton.styleFrom(backgroundColor: Brand.yellow, foregroundColor: Brand.ink),
              child: Text(_busy ? 'Placing order…' : 'Place order · ${money(total)}'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _row(String label, String value, {bool bold = false}) {
    final style = TextStyle(fontSize: bold ? 18 : 15, fontWeight: bold ? FontWeight.w800 : FontWeight.w500);
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: Row(children: [Text(label, style: style), const Spacer(), Text(value, style: style)]),
    );
  }
}
