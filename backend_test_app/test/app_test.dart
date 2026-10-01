import 'package:backend_test_app/main.dart';
import 'package:backend_test_app/state/session.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'fake_api.dart';

void main() {
  testWidgets('sign in, add a dish to the cart and place an order', (tester) async {
    SharedPreferences.setMockInitialValues({});
    tester.view.physicalSize = const Size(1170, 2532); // iPhone-sized, so overflows surface
    tester.view.devicePixelRatio = 3;
    addTearDown(tester.view.reset);

    final api = FakeApi();
    await tester.pumpWidget(ChangeNotifierProvider.value(value: Session(api), child: const LittleLemonApp()));

    // Sign in
    await tester.enterText(find.widgetWithText(TextFormField, 'Username'), 'chef');
    await tester.enterText(find.widgetWithText(TextFormField, 'Password'), 'secret');
    await tester.tap(find.widgetWithText(FilledButton, 'Sign in'));
    await tester.pumpAndSettle();
    expect(find.text("CHEF'S SPECIALS"), findsOneWidget);
    expect(find.text('Add dish'), findsOneWidget); // manager FAB

    // Filter by category
    await tester.dragUntilVisible(
        find.widgetWithText(ChoiceChip, 'Desserts'), find.byType(ChoiceChip).first, const Offset(-100, 0));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(ChoiceChip, 'Desserts'));
    await tester.pumpAndSettle();
    expect(find.text('Greek Salad'), findsNothing);

    // Add 2 × Lemon Dessert from the dish sheet
    await tester.ensureVisible(find.text('Lemon Dessert'));
    await tester.tap(find.text('Lemon Dessert'));
    await tester.pumpAndSettle();
    final sheet = find.byType(BottomSheet);
    await tester.tap(find.descendant(of: sheet, matching: find.byIcon(Icons.add)));
    await tester.pump();
    await tester.tap(find.descendant(of: sheet, matching: find.text(r'Add · $10.00')));
    await tester.pumpAndSettle();
    expect(api.cart, hasLength(1));

    // Cart shows the line and total; placing the order empties it and opens Orders
    await tester.tap(find.text('Cart'));
    await tester.pumpAndSettle();
    expect(find.text(r'2 × $5.00'), findsOneWidget);
    await tester.tap(find.text(r'Place order · $10.00'));
    await tester.pumpAndSettle();
    expect(api.cart, isEmpty);
    expect(find.text('Preparing'), findsOneWidget);
    expect(find.text('Delivered'), findsOneWidget);
  });
}
