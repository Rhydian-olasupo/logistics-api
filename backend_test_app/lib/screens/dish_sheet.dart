import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../api/models.dart';
import '../state/stores.dart';
import '../theme.dart';
import '../utils.dart';
import '../widgets/food_art.dart';

/// Bottom sheets are separate routes, so stores are passed in explicitly.
Future<void> showDishSheet(BuildContext context, MenuItem item) => showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      showDragHandle: true,
      useSafeArea: true,
      builder: (_) => ChangeNotifierProvider.value(
        value: context.read<CartStore>(),
        child: _DishSheet(item),
      ),
    );

class _DishSheet extends StatefulWidget {
  const _DishSheet(this.item);

  final MenuItem item;

  @override
  State<_DishSheet> createState() => _DishSheetState();
}

class _DishSheetState extends State<_DishSheet> {
  int _quantity = 1;
  bool _busy = false;
  String? _error;

  Future<void> _addToCart() async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await context.read<CartStore>().add(widget.item, _quantity);
      if (!mounted) return;
      final messenger = ScaffoldMessenger.of(context);
      Navigator.pop(context);
      messenger.showSnackBar(SnackBar(content: Text('Added $_quantity × ${widget.item.title}')));
    } catch (e) {
      if (mounted) {
        setState(() {
          _busy = false;
          _error = errorMessage(e); // a snackbar would be hidden behind the sheet
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final item = widget.item;
    final text = Theme.of(context).textTheme;
    return Padding(
      padding: const EdgeInsets.fromLTRB(20, 0, 20, 20),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.stretch,
        children: [
          FoodArt(item.title,
              category: item.category?.title, width: double.infinity, height: 190, radius: 20),
          const SizedBox(height: 20),
          Text(item.title, style: text.headlineSmall?.copyWith(fontWeight: FontWeight.w800)),
          if (item.category != null)
            Text(item.category!.title, style: const TextStyle(color: Colors.black54)),
          const SizedBox(height: 8),
          Text(money(item.price),
              style: text.titleLarge?.copyWith(color: Brand.green, fontWeight: FontWeight.w800)),
          if (_error != null) ...[
            const SizedBox(height: 12),
            Text(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
          ],
          const SizedBox(height: 24),
          Row(
            children: [
              _QuantityStepper(value: _quantity, onChanged: (q) => setState(() => _quantity = q)),
              const SizedBox(width: 16),
              Expanded(
                child: FilledButton(
                  onPressed: _busy ? null : _addToCart,
                  child: Text(_busy ? 'Adding…' : 'Add · ${money(item.price * _quantity)}'),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }
}

class _QuantityStepper extends StatelessWidget {
  const _QuantityStepper({required this.value, required this.onChanged});

  final int value;
  final ValueChanged<int> onChanged;

  @override
  Widget build(BuildContext context) => Container(
        height: 54,
        decoration: BoxDecoration(color: Brand.paper, borderRadius: BorderRadius.circular(16)),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            IconButton(
                onPressed: value > 1 ? () => onChanged(value - 1) : null, icon: const Icon(Icons.remove)),
            SizedBox(
              width: 24,
              child: Text('$value',
                  textAlign: TextAlign.center,
                  style: const TextStyle(fontSize: 18, fontWeight: FontWeight.w700)),
            ),
            IconButton(
                onPressed: value < 20 ? () => onChanged(value + 1) : null, icon: const Icon(Icons.add)),
          ],
        ),
      );
}
