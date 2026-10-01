import 'package:flutter/material.dart';

/// Little Lemon brand palette.
abstract final class Brand {
  static const green = Color(0xFF495E57);
  static const yellow = Color(0xFFF4CE14);
  static const salmon = Color(0xFFEE9972);
  static const peach = Color(0xFFFBDABB);
  static const ink = Color(0xFF333333);
  static const paper = Color(0xFFF7F5EF);
}

ThemeData buildTheme() {
  final base = ThemeData(
    colorScheme: ColorScheme.fromSeed(
      seedColor: Brand.green,
      primary: Brand.green,
      secondary: Brand.yellow,
      onSecondary: Brand.ink,
      surface: Colors.white,
    ),
  );
  // Derive custom text styles from the theme's own, so they keep the platform font.
  final text = base.textTheme;
  final rounded = RoundedRectangleBorder(borderRadius: BorderRadius.circular(16));
  return base.copyWith(
    scaffoldBackgroundColor: Brand.paper,
    appBarTheme: AppBarTheme(
      backgroundColor: Brand.paper,
      surfaceTintColor: Colors.transparent,
      titleTextStyle: text.headlineSmall?.copyWith(fontSize: 28, fontWeight: FontWeight.w800, color: Brand.ink),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: Brand.paper,
      border: OutlineInputBorder(borderRadius: BorderRadius.circular(14), borderSide: BorderSide.none),
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        minimumSize: const Size.fromHeight(54),
        shape: rounded,
        textStyle: text.titleMedium?.copyWith(fontWeight: FontWeight.w700),
      ),
    ),
    cardTheme: CardThemeData(color: Colors.white, elevation: 0, margin: EdgeInsets.zero, shape: rounded),
    // Floating so snackbars sit above bottom panels (e.g. the checkout button) instead of covering them.
    snackBarTheme: const SnackBarThemeData(behavior: SnackBarBehavior.floating),
    chipTheme: const ChipThemeData(shape: StadiumBorder(), side: BorderSide.none, showCheckmark: false),
    navigationBarTheme: NavigationBarThemeData(
      backgroundColor: Colors.white,
      indicatorColor: Brand.yellow.withValues(alpha: 0.5),
    ),
  );
}
