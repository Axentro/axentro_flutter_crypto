import 'package:axentro/hd_wallet.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:axentro/basic_wallet.dart';
import 'package:axentro/encrypted_wallet.dart';
import 'package:axentro/model.dart';
import 'package:axentro/network.dart';
import 'package:axentro/wallet_factory.dart';

void main() {
  final walletFactory = WalletFactory();

  test('can generate a new wallet', () {
    var basicWallet = walletFactory.generateNewWallet(Network.testnet);
    expect(basicWallet, isA<BasicWallet>());
    expect(basicWallet.hexPublicKey.value!.length, 64);
    expect(basicWallet.wif.value!.length, 96);
    expect(basicWallet.address.value!.length, 64);
  });

  test('can generate a new encrypted wallet', () {
    var ew =
        walletFactory.generateNewEncryptedWallet(Network.testnet, 'Passw0rd99');
    expect(ew, isA<EncryptedWallet>());
  });

  test('can generate a new hd wallet', () async {
    var hdWallet = await walletFactory.generateNewHdWallet(Network.testnet);
    expect(hdWallet, isA<HdWallet>());
    expect(hdWallet.hexPrivateKey.value!.length, 64);
    expect(hdWallet.hexPublicKey.value!.length, 64);
    expect(hdWallet.wif.value!.length, 96);
    expect(hdWallet.address.value!.length, 64);
  });

  test('can recover an hd wallet from a mnemonic', () async {
    var hdWallet = await walletFactory.generateNewHdWallet(Network.testnet);
    var mnemonic = hdWallet.mnemonic!;
    var recoveredHdWallet = await walletFactory.recoverHdWalletFromMnemonic(
        mnemonic, Network.testnet);
    expect(recoveredHdWallet.hexPrivateKey, hdWallet.hexPrivateKey);
  });

  test('can generate a new encrypted hd wallet', () async {
    var ew = await walletFactory.generateNewEncryptedHdWallet(
        Network.testnet, 'Passw0rd99');
    expect(ew, isA<EncryptedWallet>());
  });

  test('can generate correct WIF', () {
    HexPrivateKey hexPrivateKey = HexPrivateKey(
        'f92913f355539a6ec6129b744a9e1dcb4d3c8df29cccb8066d57c454cead6fe4');
    NetworkPrefix networkPrefix = NetworkPrefix('M0');
    Wif expectedWif = Wif(
        'TTBmOTI5MTNmMzU1NTM5YTZlYzYxMjliNzQ0YTllMWRjYjRkM2M4ZGYyOWNjY2I4MDY2ZDU3YzQ1NGNlYWQ2ZmU0MjdlYzNl');

    var wif = walletFactory.generateWif(hexPrivateKey, networkPrefix);
    expect(wif, expectedWif);
  });

  test('can generate correct Address', () {
    HexPublicKey hexPublicKey = HexPublicKey(
        '049ec703e3eab6beba4b1ea5745da006ecce8a556144cfb7d8bbbe0f31896c08f9aac3aee3410b38fe61b6cfc5afd447faa1ca051f1e0adf1d466addf55fc77d50');
    NetworkPrefix networkPrefix = NetworkPrefix('M0');
    Address expectedAddress = Address(
        'TTAzZGQxYzhmMDMyYmFhM2VmZDBmNTI5YTRmNTY0MjVhOWI3NjljOGYwODgyNDlk');

    var address = walletFactory.generateAddress(hexPublicKey, networkPrefix);
    expect(address, expectedAddress);
  });

  test('can get privatekey and network from wif', () {
    Wif wif = Wif(
        'TTBmOTI5MTNmMzU1NTM5YTZlYzYxMjliNzQ0YTllMWRjYjRkM2M4ZGYyOWNjY2I4MDY2ZDU3YzQ1NGNlYWQ2ZmU0MjdlYzNl');
    HexPrivateKey expectedPrivateKey = HexPrivateKey(
        'f92913f355539a6ec6129b744a9e1dcb4d3c8df29cccb8066d57c454cead6fe4');
    NetworkPrefix expectedNetwork = NetworkPrefix('M0');

    var networkPrivateKey = walletFactory.getPrivateKeyAndNetworkFromWif(wif);
    expect(networkPrivateKey.hexPrivateKey, expectedPrivateKey);
    expect(networkPrivateKey.networkPrefix, expectedNetwork);
  });

  test('can get publickey from privatekey', () async {
    var kp = walletFactory.generateKeyPair();
    HexPublicKey expectedHexPublicKey = kp.hexPublicKey;
    HexPrivateKey hexPrivateKey = kp.hexPrivateKey;
    var hexPublicKey =
        await walletFactory.getPublicKeyFromPrivateKey(hexPrivateKey);
    expect(hexPublicKey, expectedHexPublicKey);
  });

  test('can get basic wallet from wif', () async {
    var kp = walletFactory.generateKeyPair();
    HexPublicKey hexPublicKey = kp.hexPublicKey;
    HexPrivateKey hexPrivateKey = kp.hexPrivateKey;
    NetworkPrefix networkPrefix = NetworkPrefix('M0');

    var wif = walletFactory.generateWif(hexPrivateKey, networkPrefix);
    var address = walletFactory.generateAddress(hexPublicKey, networkPrefix);
    var basicWallet = await walletFactory.getWalletFromWif(wif);

    expect(basicWallet.hexPublicKey, hexPublicKey);
    expect(basicWallet.wif, wif);
    expect(basicWallet.address, address);
  });

  test('can get full wallet from wif', () async {
    var kp = walletFactory.generateKeyPair();
    HexPublicKey hexPublicKey = kp.hexPublicKey;
    HexPrivateKey hexPrivateKey = kp.hexPrivateKey;
    NetworkPrefix networkPrefix = NetworkPrefix('M0');

    var wif = walletFactory.generateWif(hexPrivateKey, networkPrefix);
    var address = walletFactory.generateAddress(hexPublicKey, networkPrefix);
    var basicWallet = await walletFactory.getFullWalletFromWif(wif);

    expect(basicWallet.hexPrivateKey, hexPrivateKey);
    expect(basicWallet.hexPublicKey, hexPublicKey);
    expect(basicWallet.wif, wif);
    expect(basicWallet.address, address);
  });

  test('can encrypt a wallet', () {
    var basicWallet = walletFactory.generateNewWallet(Network.testnet);
    var ew = walletFactory.encryptWallet(basicWallet, "Passw0rd99");
    expect(ew, isA<EncryptedWallet>());
    expect(ew.address, basicWallet.address);
  });

  test('can decrypt a wallet', () {
    String password = "Passw0rd99";
    var basicWallet = walletFactory.generateNewWallet(Network.testnet);
    var ew = walletFactory.encryptWallet(basicWallet, password);
    var bw = walletFactory.decryptWallet(ew, password);
    expect(basicWallet, isA<BasicWallet>());
    expect(bw, basicWallet);
  });

  test('can encrypt an hd wallet', () async {
    var hdWallet = await walletFactory.generateNewHdWallet(Network.testnet);
    var ew = walletFactory.encryptHdWallet(hdWallet, "Passw0rd99");
    expect(ew, isA<EncryptedWallet>());
    expect(ew.address, hdWallet.address);
  });

  test('can decrypt an hd wallet', () async {
    String password = "Passw0rd99";
    var hdWallet = await walletFactory.generateNewHdWallet(Network.testnet);
    var ew = walletFactory.encryptHdWallet(hdWallet, password);
    var hdw = walletFactory.decryptHdWallet(ew, password);
    expect(hdw, isA<HdWallet>());
    expect(hdw, hdWallet);
  });
}
