import 'package:convert/convert.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;

import 'model.dart';

/// This holds an EDDSA keypair
/// * publicKey
/// * privateKey
class KeyPair {
  ed.PublicKey publicKey;
  ed.PrivateKey privateKey;

  KeyPair(ed.KeyPair keyPair) {
    this.publicKey = keyPair.publicKey;
    this.privateKey = ed.PrivateKey(keyPair.privateKey.bytes.sublist(0, 32));
  }

  /// Returns the publicKey in hex format
  HexPublicKey get hexPublicKey {
    return HexPublicKey(hex.encode(publicKey.bytes));
  }

  /// Returns the privateKey in hex format
  HexPrivateKey get hexPrivateKey {
    return HexPrivateKey(hex.encode(privateKey.bytes));
  }
}
