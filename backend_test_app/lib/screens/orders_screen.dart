import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import 'package:provider/provider.dart';

import '../api/models.dart';
import '../state/session.dart';
import '../theme.dart';
import '../utils.dart';
import '../widgets/common.dart';

class OrdersScreen extends StatefulWidget {
  const OrdersScreen({super.key});

  @override
  State<OrdersScreen> createState() => _OrdersScreenState();
}

class _OrdersScreenState extends State<OrdersScreen> {
  late Future<List<Order>> _orders = _load();

  Future<List<Order>> _load() async {
    final rows = await context.read<Session>().api.get('/api/orders') as List? ?? const [];
    return [for (final r in rows) Order.fromJson(r)]..sort((a, b) => b.date.compareTo(a.date));
  }

  Future<void> _refresh() async {
    final next = _load();
    setState(() => _orders = next);
    await next;
  }

  @override
  Widget build(BuildContext context) => Scaffold(
        appBar: AppBar(title: const Text('Orders')),
        body: FutureBuilder(
          future: _orders,
          builder: (context, snap) {
            // Keep showing the previous list while a refresh is in flight.
            if (snap.hasError) {
              return EmptyState(
                icon: Icons.wifi_off,
                title: "Couldn't load your orders",
                message: errorMessage(snap.error!),
                action: TextButton(onPressed: _refresh, child: const Text('Try again')),
              );
            }
            if (!snap.hasData) return const Center(child: CircularProgressIndicator());

            final orders = snap.data!;
            return RefreshIndicator(
              onRefresh: _refresh,
              child: orders.isEmpty
                  ? ListView(children: const [
                      SizedBox(height: 80),
                      EmptyState(
                        icon: Icons.receipt_long_outlined,
                        title: 'No orders yet',
                        message: 'Your orders will show up here.',
                      ),
                    ])
                  : ListView.separated(
                      padding: const EdgeInsets.all(20),
                      itemCount: orders.length,
                      separatorBuilder: (_, __) => const SizedBox(height: 12),
                      itemBuilder: (_, i) => _OrderCard(orders[i]),
                    ),
            );
          },
        ),
      );
}

class _OrderCard extends StatelessWidget {
  const _OrderCard(this.order);

  final Order order;

  static final _date = DateFormat('MMM d · h:mm a');

  @override
  Widget build(BuildContext context) => Card(
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Row(
            children: [
              const CircleAvatar(
                backgroundColor: Brand.peach,
                child: Icon(Icons.receipt_long, color: Brand.ink),
              ),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('Order #${order.number}',
                        style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w700)),
                    Text(_date.format(order.date), style: const TextStyle(color: Colors.black54)),
                  ],
                ),
              ),
              Column(
                crossAxisAlignment: CrossAxisAlignment.end,
                children: [
                  Text(money(order.total), style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w800)),
                  const SizedBox(height: 6),
                  _StatusPill(delivered: order.delivered),
                ],
              ),
            ],
          ),
        ),
      );
}

class _StatusPill extends StatelessWidget {
  const _StatusPill({required this.delivered});

  final bool delivered;

  @override
  Widget build(BuildContext context) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
        decoration: BoxDecoration(
          color: delivered ? Brand.green.withValues(alpha: 0.15) : Brand.yellow.withValues(alpha: 0.35),
          borderRadius: BorderRadius.circular(20),
        ),
        child: Text(
          delivered ? 'Delivered' : 'Preparing',
          style: TextStyle(
            fontSize: 12,
            fontWeight: FontWeight.w700,
            color: delivered ? Brand.green : Brand.ink,
          ),
        ),
      );
}
