import 'package:flutter_test/flutter_test.dart';
import 'package:axentro/model.dart';
import 'package:axentro/wallet_factory.dart';

void main() {
  test('can generate a keypair', () {
    var kp = WalletFactory().generateKeyPair();
    HexPublicKey hexPublicKey = kp.hexPublicKey;
    HexPrivateKey hexPrivateKey = kp.hexPrivateKey;

    expect(hexPrivateKey.value.length, 64);
    expect(hexPublicKey.value.length, 64);
  });
}
