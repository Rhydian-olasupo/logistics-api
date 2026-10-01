import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../state/stores.dart';
import '../utils.dart';
import '../widgets/common.dart';

/// Manager-only tools for editing the menu.

Future<void> addCategory(BuildContext context) async {
  final menu = context.read<MenuStore>();
  final title = await showTextPrompt(context, title: 'New category', label: 'Name, e.g. Mains');
  if (title == null || title.isEmpty) return;
  try {
    await menu.addCategory(title);
    if (context.mounted) showSnack(context, 'Added "$title"');
  } catch (e) {
    if (context.mounted) showError(context, e);
  }
}

Future<void> showAddDishSheet(BuildContext context) => showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      showDragHandle: true,
      useSafeArea: true,
      builder: (_) => ChangeNotifierProvider.value(
        value: context.read<MenuStore>(),
        child: const _AddDishSheet(),
      ),
    );

class _AddDishSheet extends StatefulWidget {
  const _AddDishSheet();

  @override
  State<_AddDishSheet> createState() => _AddDishSheetState();
}

class _AddDishSheetState extends State<_AddDishSheet> {
  final _form = GlobalKey<FormState>();
  final _title = TextEditingController();
  final _price = TextEditingController();
  String? _categoryId;
  bool _featured = false;
  bool _busy = false;
  String? _error;

  @override
  void dispose() {
    _title.dispose();
    _price.dispose();
    super.dispose();
  }

  Future<void> _save() async {
    if (!_form.currentState!.validate()) return;
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      await context.read<MenuStore>().addItem(
            title: _title.text.trim(),
            price: double.parse(_price.text),
            categoryId: _categoryId!,
            featured: _featured,
          );
      if (!mounted) return;
      final messenger = ScaffoldMessenger.of(context);
      Navigator.pop(context);
      messenger.showSnackBar(SnackBar(content: Text('${_title.text.trim()} is on the menu')));
    } catch (e) {
      if (mounted) {
        setState(() {
          _busy = false;
          _error = errorMessage(e);
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final categories = context.watch<MenuStore>().categories;
    return Padding(
      padding: EdgeInsets.fromLTRB(20, 0, 20, 20 + MediaQuery.viewInsetsOf(context).bottom),
      child: Form(
        key: _form,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            const Text('New dish', style: TextStyle(fontSize: 24, fontWeight: FontWeight.w800)),
            const SizedBox(height: 16),
            TextFormField(
              controller: _title,
              textCapitalization: TextCapitalization.words,
              decoration: const InputDecoration(labelText: 'Name'),
              validator: (v) => v!.trim().isEmpty ? 'Give the dish a name' : null,
            ),
            const SizedBox(height: 12),
            TextFormField(
              controller: _price,
              keyboardType: const TextInputType.numberWithOptions(decimal: true),
              decoration: const InputDecoration(labelText: 'Price', prefixText: '\$ '),
              validator: (v) => (double.tryParse(v!) ?? 0) > 0 ? null : 'Enter a price',
            ),
            const SizedBox(height: 12),
            DropdownButtonFormField<String>(
              initialValue: _categoryId,
              decoration: const InputDecoration(labelText: 'Category'),
              items: [for (final c in categories) DropdownMenuItem(value: c.id, child: Text(c.title))],
              onChanged: (id) => _categoryId = id,
              validator: (id) => id == null ? 'Pick a category' : null,
            ),
            Align(
              alignment: Alignment.centerLeft,
              child: TextButton.icon(
                onPressed: () => addCategory(context),
                icon: const Icon(Icons.add, size: 18),
                label: const Text('New category'),
              ),
            ),
            SwitchListTile(
              contentPadding: EdgeInsets.zero,
              title: const Text("Chef's special"),
              subtitle: const Text('Shown in the featured carousel'),
              value: _featured,
              onChanged: (v) => setState(() => _featured = v),
            ),
            if (_error != null)
              Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Text(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
              ),
            const SizedBox(height: 8),
            FilledButton(
              onPressed: _busy ? null : _save,
              child: Text(_busy ? 'Saving…' : 'Add to menu'),
            ),
          ],
        ),
      ),
    );
  }
}
