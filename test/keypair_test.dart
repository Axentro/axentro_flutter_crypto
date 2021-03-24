import 'package:flutter_test/flutter_test.dart';
import 'package:axentro/model.dart';
import 'package:axentro/wallet_factory.dart';

import 'test_helper.dart';

void main() {
  test('can generate a keypair', () {
    WalletFactory().generateKeyPair().fold(TestHelper.handleError, (kp){
      HexPublicKey hexPublicKey  = kp.hexPublicKey;
      HexPrivateKey hexPrivateKey = kp.hexPrivateKey;

      expect(hexPrivateKey.value.length, 128);
      expect(hexPublicKey.value.length, 64);
    });
  });
}
