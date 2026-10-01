import 'package:flutter/material.dart';

import '../theme.dart';

/// The API has no images, so each dish gets an icon matched from its name (or category)
/// on a stable gradient derived from the name.
class FoodArt extends StatelessWidget {
  const FoodArt(this.title, {super.key, this.category, this.width, this.height = 84, this.radius = 16});

  final String title;
  final String? category;
  final double? width;
  final double height;
  final double radius;

  static const _iconsByKeyword = {
    'salad': Icons.eco,
    'fish': Icons.set_meal,
    'seafood': Icons.set_meal,
    'pizza': Icons.local_pizza,
    'burger': Icons.lunch_dining,
    'sandwich': Icons.lunch_dining,
    'bread': Icons.bakery_dining,
    'bruschetta': Icons.bakery_dining,
    'pastry': Icons.bakery_dining,
    'soup': Icons.soup_kitchen,
    'noodle': Icons.ramen_dining,
    'ramen': Icons.ramen_dining,
    'rice': Icons.rice_bowl,
    'kebab': Icons.kebab_dining,
    'grill': Icons.outdoor_grill,
    'pasta': Icons.dinner_dining,
    'ice cream': Icons.icecream,
    'cake': Icons.cake,
    'dessert': Icons.cake,
    'coffee': Icons.local_cafe,
    'tea': Icons.emoji_food_beverage,
    'drink': Icons.local_drink,
    'juice': Icons.local_drink,
    'wine': Icons.wine_bar,
    'starter': Icons.tapas,
    'main': Icons.restaurant,
  };

  static const _gradients = [
    [Brand.peach, Brand.salmon],
    [Color(0xFFFFE89A), Color(0xFFE9B800)],
    [Color(0xFFB9D3C2), Brand.green],
    [Color(0xFFFFD3B5), Color(0xFFE8825A)],
  ];

  IconData get _icon {
    // Title first ("Grilled Fish" → fish), then category ("Desserts" → dessert).
    for (final text in [title, category ?? '']) {
      final lower = text.toLowerCase();
      for (final MapEntry(:key, :value) in _iconsByKeyword.entries) {
        if (lower.contains(key)) return value;
      }
    }
    return Icons.restaurant_menu;
  }

  @override
  Widget build(BuildContext context) {
    // String.hashCode isn't guaranteed stable across runs, so hash the characters ourselves.
    final seed = title.codeUnits.fold(17, (h, c) => (h * 131 + c) % 1000003);
    return Container(
      width: width ?? height,
      height: height,
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(radius),
        gradient: LinearGradient(
          colors: _gradients[seed % _gradients.length],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
      ),
      child: Icon(_icon, size: height * 0.45, color: Colors.white.withValues(alpha: 0.92)),
    );
  }
}
