import 'package:quiver/core.dart';

import 'model.dart';

/// HdWallet holds the hd wallet information which consists of:
/// * hexPrivateKey - the private key in hex format
/// * hexPublicKey - the public key in hex format
/// * wif - the Wallet Information Format (contains the private key within)
/// * address - the Base64 encoded address
/// * seed - the seed the master wallet was generated from
class HdWallet {
  HexPrivateKey hexPrivateKey;
  HexPublicKey hexPublicKey;
  Wif wif;
  Address address;
  String seed;
  String mnemonic;

  HdWallet(
      this.hexPrivateKey, this.hexPublicKey, this.wif, this.address, this.seed, this.mnemonic);

  HdWallet.fromJson(Map<String, dynamic> json)
      : hexPrivateKey = HexPrivateKey(json['hexPrivateKey']),
        hexPublicKey = HexPublicKey(json['hexPublicKey']),
        wif = Wif(json['wif']),
        address = Address(json['address']),
        seed = json['seed'],
        mnemonic = json['mnemonic'];

  Map<String, dynamic> toJson() => {
        'hexPrivateKey': hexPrivateKey.value,
        'hexPublicKey': hexPublicKey.value,
        'wif': wif.value,
        'address': address.value,
        'seed': seed,
        'mnemonic': mnemonic
      };

  bool operator ==(o) =>
      o is HdWallet &&
      o.hexPrivateKey.value == hexPrivateKey.value &&
      o.hexPublicKey.value == hexPublicKey.value &&
      o.wif.value == wif.value &&
      o.address.value == address.value &&
      o.seed == seed &&
      o.mnemonic == mnemonic;

  int get hashCode => hashObjects([
        hexPrivateKey.hashCode,
        hexPublicKey.hashCode,
        wif.hashCode,
        address.hashCode,
        seed.hashCode,
        mnemonic.hashCode
      ]);
}
