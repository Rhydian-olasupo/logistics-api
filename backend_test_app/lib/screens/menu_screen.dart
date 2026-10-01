import 'package:flutter/material.dart';
import 'package:provider/provider.dart';

import '../api/models.dart';
import '../state/session.dart';
import '../state/stores.dart';
import '../theme.dart';
import '../utils.dart';
import '../widgets/common.dart';
import '../widgets/food_art.dart';
import 'dish_sheet.dart';
import 'manage_menu.dart';

class MenuScreen extends StatefulWidget {
  const MenuScreen({super.key});

  @override
  State<MenuScreen> createState() => _MenuScreenState();
}

class _MenuScreenState extends State<MenuScreen> {
  String _query = '';
  String? _categoryId; // null = all categories

  @override
  Widget build(BuildContext context) {
    final menu = context.watch<MenuStore>();
    final isManager = context.select<Session, bool>((s) => s.isManager);
    final browsing = _query.isEmpty && _categoryId == null;
    final featured = browsing ? menu.items.where((i) => i.featured).toList() : const <MenuItem>[];
    final items = menu.items
        .where((i) => _categoryId == null || i.category?.id == _categoryId)
        .where((i) => i.title.toLowerCase().contains(_query.toLowerCase()))
        .toList();

    return Scaffold(
      floatingActionButton: isManager
          ? FloatingActionButton.extended(
              onPressed: () => showAddDishSheet(context),
              icon: const Icon(Icons.add),
              label: const Text('Add dish'),
            )
          : null,
      body: RefreshIndicator(
        onRefresh: menu.load,
        child: CustomScrollView(
          physics: const AlwaysScrollableScrollPhysics(),
          slivers: [
            SliverToBoxAdapter(child: _Banner(onSearch: (q) => setState(() => _query = q))),
            const SliverPadding(
              padding: EdgeInsets.symmetric(horizontal: 16),
              sliver: SliverToBoxAdapter(child: SectionLabel('Order for delivery!')),
            ),
            SliverToBoxAdapter(
              child: _CategoryChips(
                categories: menu.categories,
                selected: _categoryId,
                onSelected: (id) => setState(() => _categoryId = id),
              ),
            ),
            if (featured.isNotEmpty) ...[
              const SliverPadding(
                padding: EdgeInsets.symmetric(horizontal: 16),
                sliver: SliverToBoxAdapter(child: SectionLabel('Chef\'s specials')),
              ),
              SliverToBoxAdapter(
                child: SizedBox(
                  height: 196,
                  child: ListView.separated(
                    scrollDirection: Axis.horizontal,
                    padding: const EdgeInsets.symmetric(horizontal: 20),
                    itemCount: featured.length,
                    separatorBuilder: (_, __) => const SizedBox(width: 12),
                    itemBuilder: (_, i) => _FeaturedCard(featured[i]),
                  ),
                ),
              ),
              const SliverToBoxAdapter(child: SizedBox(height: 8)),
            ],
            if (menu.loading && menu.items.isEmpty)
              const SliverFillRemaining(
                  hasScrollBody: false, child: Center(child: CircularProgressIndicator()))
            else if (menu.error != null && menu.items.isEmpty)
              SliverFillRemaining(
                hasScrollBody: false,
                child: EmptyState(
                  icon: Icons.wifi_off,
                  title: "Couldn't load the menu",
                  message: errorMessage(menu.error!),
                  action: TextButton(onPressed: menu.load, child: const Text('Try again')),
                ),
              )
            else if (items.isEmpty)
              SliverFillRemaining(
                hasScrollBody: false,
                child: EmptyState(
                  icon: Icons.no_food_outlined,
                  title: menu.items.isEmpty ? 'The menu is empty' : 'No dishes match',
                  message: menu.items.isEmpty && isManager ? 'Tap "Add dish" to create the first one.' : null,
                ),
              )
            else
              SliverList.separated(
                itemCount: items.length,
                itemBuilder: (_, i) => _DishTile(items[i], canDelete: isManager),
                separatorBuilder: (_, __) => const Divider(height: 1, indent: 20, endIndent: 20),
              ),
            const SliverToBoxAdapter(child: SizedBox(height: 96)),
          ],
        ),
      ),
    );
  }
}

class _Banner extends StatelessWidget {
  const _Banner({required this.onSearch});

  final ValueChanged<String> onSearch;

  @override
  Widget build(BuildContext context) => Container(
        color: Brand.green,
        padding: EdgeInsets.fromLTRB(20, MediaQuery.paddingOf(context).top + 20, 20, 24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Little Lemon',
                style: TextStyle(color: Brand.yellow, fontSize: 40, fontWeight: FontWeight.w800, height: 1)),
            const Text('Chicago', style: TextStyle(color: Colors.white, fontSize: 24)),
            const SizedBox(height: 12),
            const Text(
              'A family-owned Mediterranean restaurant, focused on traditional recipes '
              'served with a modern twist.',
              style: TextStyle(color: Colors.white70, fontSize: 15, height: 1.4),
            ),
            const SizedBox(height: 20),
            TextField(
              onChanged: onSearch,
              decoration: const InputDecoration(
                hintText: 'Search the menu',
                prefixIcon: Icon(Icons.search),
                fillColor: Colors.white,
              ),
            ),
          ],
        ),
      );
}

class _CategoryChips extends StatelessWidget {
  const _CategoryChips({required this.categories, required this.selected, required this.onSelected});

  final List<Category> categories;
  final String? selected;
  final ValueChanged<String?> onSelected;

  @override
  Widget build(BuildContext context) => SizedBox(
        height: 44,
        child: ListView(
          scrollDirection: Axis.horizontal,
          padding: const EdgeInsets.symmetric(horizontal: 20),
          children: [
            for (final c in [null, ...categories])
              Padding(
                padding: const EdgeInsets.only(right: 8),
                child: ChoiceChip(
                  label: Text(c?.title ?? 'All'),
                  selected: selected == c?.id,
                  onSelected: (_) => onSelected(c?.id),
                  backgroundColor: Colors.white,
                  selectedColor: Brand.yellow,
                  labelStyle: const TextStyle(fontWeight: FontWeight.w700, color: Brand.ink),
                ),
              ),
          ],
        ),
      );
}

class _FeaturedCard extends StatelessWidget {
  const _FeaturedCard(this.item);

  final MenuItem item;

  @override
  Widget build(BuildContext context) => SizedBox(
        width: 160,
        child: Card(
          clipBehavior: Clip.antiAlias,
          child: InkWell(
            onTap: () => showDishSheet(context, item),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                FoodArt(item.title, category: item.category?.title, width: 160, height: 116, radius: 0),
                Padding(
                  padding: const EdgeInsets.all(12),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(item.title,
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                          style: const TextStyle(fontWeight: FontWeight.w700)),
                      const SizedBox(height: 4),
                      Text(money(item.price),
                          style: const TextStyle(color: Brand.green, fontWeight: FontWeight.w800)),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ),
      );
}

class _DishTile extends StatelessWidget {
  const _DishTile(this.item, {required this.canDelete});

  final MenuItem item;
  final bool canDelete;

  Future<void> _confirmDelete(BuildContext context) async {
    final menu = context.read<MenuStore>();
    final ok = await showDialog<bool>(
      context: context,
      builder: (context) => AlertDialog(
        title: Text('Remove ${item.title}?'),
        content: const Text('It will disappear from the menu for everyone.'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
          TextButton(onPressed: () => Navigator.pop(context, true), child: const Text('Remove')),
        ],
      ),
    );
    if (ok != true) return;
    try {
      await menu.deleteItem(item);
    } catch (e) {
      if (context.mounted) showError(context, e);
    }
  }

  @override
  Widget build(BuildContext context) => InkWell(
        onTap: () => showDishSheet(context, item),
        onLongPress: canDelete ? () => _confirmDelete(context) : null,
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
          child: Row(
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(children: [
                      Flexible(
                        child: Text(item.title,
                            style: const TextStyle(fontSize: 17, fontWeight: FontWeight.w700)),
                      ),
                      if (item.featured) ...[
                        const SizedBox(width: 6),
                        const Icon(Icons.star_rounded, size: 18, color: Brand.yellow),
                      ],
                    ]),
                    if (item.category != null)
                      Text(item.category!.title, style: const TextStyle(color: Colors.black54)),
                    const SizedBox(height: 8),
                    Text(money(item.price),
                        style:
                            const TextStyle(color: Brand.green, fontSize: 16, fontWeight: FontWeight.w800)),
                  ],
                ),
              ),
              const SizedBox(width: 16),
              FoodArt(item.title, category: item.category?.title),
            ],
          ),
        ),
      );
}
