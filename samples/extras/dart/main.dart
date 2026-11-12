// RevLens Dart AOT fixture
class Account {
  final String owner;
  int balance;
  Account(this.owner, this.balance);
  bool withdraw(int amount) {
    if (amount > balance) { print('insufficient funds for $owner'); return false; }
    balance -= amount;
    return true;
  }
  @override
  String toString() => 'Account($owner, $balance)';
}
abstract class Shape { double area(); }
class Circle extends Shape { final double r; Circle(this.r); @override double area() => 3.14159 * r * r; }
class Square extends Shape { final double s; Square(this.s); @override double area() => s * s; }
String checkPassword(String input) => input == 'hunter2-revlens' ? 'access granted' : 'access denied';
void main(List<String> args) {
  final a = Account('alice', 100);
  a.withdraw(30);
  print(a);
  final shapes = <Shape>[Circle(2), Square(3)];
  for (final s in shapes) print('area ${s.area()}');
  print(checkPassword(args.isEmpty ? 'guess' : args.first));
  print(const {'api': 'https://api.example.com/v1/login', 'mode': 'release'});
}
