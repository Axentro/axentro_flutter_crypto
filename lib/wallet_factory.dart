library sushichain;

import 'dart:async';
import 'dart:convert';
import "dart:typed_data";

import 'package:axentro/model.dart';
import 'package:axentro/network.dart';
import 'package:axentro/hd_wallet.dart';
import 'package:axentro/network_pkey.dart';
import 'package:convert/convert.dart';
import 'package:crypto/crypto.dart';
import 'package:ed25519_edwards/ed25519_edwards.dart' as ed;
import 'package:pointycastle/api.dart';
import 'package:pointycastle/digests/ripemd160.dart';
import 'package:bip39/bip39.dart' as bip39;
import "package:ed25519_hd_key/ed25519_hd_key.dart";

import 'full_wallet.dart';
import 'basic_wallet.dart';
import 'encrypted_wallet.dart';
import 'keypair.dart';
import 'model.dart';
import 'network.dart';

/// WalletFactory has several functions that assist with Axentro based
/// crypto such as wallet generation, signing, verifying etc
class WalletFactory {
  /// Generates an EDDSA ED25519 key pair
  ///
  /// KeyPair keyPair = new WalletFactory().generateKeyPair();
  KeyPair generateKeyPair() {
    return KeyPair(ed.generateKey());
  }

  /// Generates a new wallet for the network provided
  ///
  /// BasicWallet basicWallet = new WalletFactory().generateNewWallet(Network.testnet);
  BasicWallet generateNewWallet(Network network) {
    NetworkPrefix networkPrefix = NetworkUtil.networkPrefix(network);
    KeyPair keyPair = generateKeyPair();

    return _toBasicWallet(networkPrefix, keyPair);
  }

  /// Generates a new encrypted wallet for the specified network with the supplied password
  ///
  /// EncryptedWallet encryptedWallet = new WalletFactory().generateNewEncryptedWallet(Network.testnet, 'password');
  EncryptedWallet generateNewEncryptedWallet(Network network, String password) {
    return encryptWallet(generateNewWallet(network), password);
  }

  /// Generates a new hd wallet for the network provided
  ///
  /// Future<HdWallet> hdWallet = await new WalletFactory().generateNewHdWallet(Network.testnet);
  Future<HdWallet> generateNewHdWallet(Network network) async {
    NetworkPrefix networkPrefix = NetworkUtil.networkPrefix(network);

    var mnemonic = bip39.generateMnemonic();
    var seedBytes = bip39.mnemonicToSeed(mnemonic);
    KeyData master = await ED25519_HD_KEY.getMasterKeyFromSeed(seedBytes);
    var hexPrivateKey = HexPrivateKey(hex.encode(master.key));
    var hexPublicKey = HexPublicKey(
        hex.encode(await ED25519_HD_KEY.getPublicKey(master.key, false)));
    var hexSeed = bip39.mnemonicToSeedHex(mnemonic);

    return _toHdWallet(
        networkPrefix, hexPrivateKey, hexPublicKey, hexSeed, mnemonic);
  }

  /// Recovers an hd wallet from a mnemonic and target network
  ///
  /// Future<HdWallet> hdWallet = await new WalletFactory().recoverHdWalletFromMnemonic(mnemonic, Network.testnet));
  Future<HdWallet> recoverHdWalletFromMnemonic(
      String mnemonic, Network network) async {
    NetworkPrefix networkPrefix = NetworkUtil.networkPrefix(network);
    var seedBytes = bip39.mnemonicToSeed(mnemonic);
    KeyData master = await ED25519_HD_KEY.getMasterKeyFromSeed(seedBytes);
    var hexPrivateKey = HexPrivateKey(hex.encode(master.key));
    var hexPublicKey = HexPublicKey(
        hex.encode(await ED25519_HD_KEY.getPublicKey(master.key, false)));
    var hexSeed = bip39.mnemonicToSeedHex(mnemonic);
    return _toHdWallet(
        networkPrefix, hexPrivateKey, hexPublicKey, hexSeed, mnemonic);
  }

  /// Generates a new encrypted wallet for the specified network with the supplied password
  ///
  /// Future<EncryptedHdWallet> encryptedHdWallet = await new WalletFactory().generateNewEncryptedHdWallet(Network.testnet, 'password');
  Future<EncryptedWallet> generateNewEncryptedHdWallet(
      Network network, String password) async {
    var hdWallet = await generateNewHdWallet(network);
    return encryptHdWallet(hdWallet, password);
  }

  HdWallet _toHdWallet(NetworkPrefix networkPrefix, HexPrivateKey hexPrivateKey,
      HexPublicKey hexPublicKey, String hexSeed, String mnemonic) {
    var wif = generateWif(hexPrivateKey, networkPrefix);
    var address = generateAddress(hexPublicKey, networkPrefix);

    return HdWallet(
        hexPrivateKey, hexPublicKey, wif, address, hexSeed, mnemonic);
  }

  BasicWallet _toBasicWallet(NetworkPrefix networkPrefix, KeyPair keyPair) {
    HexPublicKey hexPublicKey = keyPair.hexPublicKey;
    HexPrivateKey hexPrivateKey = keyPair.hexPrivateKey;

    var wif = generateWif(hexPrivateKey, networkPrefix);
    var address = generateAddress(hexPublicKey, networkPrefix);

    return BasicWallet(hexPublicKey, wif, address);
  }

  /// Generates a WIF given a hexPrivateKey and target network
  ///
  /// Wif wif = new WalletFactory().generateWif(hexPrivateKey, Network.testnet);
  Wif generateWif(HexPrivateKey hexPrivateKey, NetworkPrefix networkPrefix) {
    String networkKey = networkPrefix.value! + hexPrivateKey.value!;
    String hashedKey = _toSha256(_toSha256(networkKey));
    String checkSum = hashedKey.substring(0, 6);
    return Wif(_toBase64(networkKey + checkSum));
  }

  /// Generates an address given a hexPublicKey and target network
  ///
  /// Address address = new WalletFactory().generateAddress(hexPublicKey, Network.testnet);
  Address generateAddress(
      HexPublicKey hexPublicKey, NetworkPrefix networkPrefix) {
    String hashedAddress = _toRipeMd160(_toSha256(hexPublicKey.value!));
    String networkAddress = networkPrefix.value! + hashedAddress;
    String hashedAddressAgain = _toSha256(_toSha256(networkAddress));
    String checksum = hashedAddressAgain.substring(0, 6);
    return Address(_toBase64(networkAddress + checksum));
  }

  /// Gets a wallet from the supplied wif
  ///
  /// Future<BasicWallet> basicWallet = await new WalletFactory().getWalletFromWif(wif);
  Future<BasicWallet> getWalletFromWif(Wif wif) async {
    var networkPrivateKey = getPrivateKeyAndNetworkFromWif(wif);
    HexPrivateKey hexPrivateKey = networkPrivateKey.hexPrivateKey!;
    NetworkPrefix networkPrefix = networkPrivateKey.networkPrefix!;

    var hexPublicKey = await getPublicKeyFromPrivateKey(hexPrivateKey);
    var address = generateAddress(hexPublicKey, networkPrefix);
    return BasicWallet(hexPublicKey, wif, address);
  }

  /// Gets a full wallet from the supplied wif
  ///
  /// Future<FullWallet> fullWallet = await new WalletFactory().getFullWalletFromWif(wif);
  Future<FullWallet> getFullWalletFromWif(Wif wif) async {
    var networkPrivateKey = getPrivateKeyAndNetworkFromWif(wif);
    HexPrivateKey hexPrivateKey = networkPrivateKey.hexPrivateKey!;
    NetworkPrefix networkPrefix = networkPrivateKey.networkPrefix!;
    var hexPublicKey = await getPublicKeyFromPrivateKey(hexPrivateKey);
    var address = generateAddress(hexPublicKey, networkPrefix);
    return FullWallet(hexPublicKey, hexPrivateKey, wif, address, networkPrefix);
  }

  /// Encrypts a basic wallet
  ///
  /// EncryptedWallet encryptedBasicWallet = new WalletFactory().encryptWallet(wallet, password);
  EncryptedWallet encryptWallet(BasicWallet wallet, String password) {
    String walletJson = json.encode(wallet);

    var key = _toSha256I(password);
    var iv = _toSha256I(walletJson).sublist(0, 16);
    CipherParameters params = new PaddedBlockCipherParameters(
        new ParametersWithIV(new KeyParameter(key as Uint8List), iv as Uint8List), null);

    BlockCipher encryptionCipher = new PaddedBlockCipher("AES/CBC/PKCS7");
    encryptionCipher.init(true, params);
    Uint8List encrypted = encryptionCipher.process(utf8.encode(walletJson) as Uint8List);
    String cipherText = hex.encode(encrypted);

    return EncryptedWallet(Source("flutter"), CipherText(cipherText),
        wallet.address, Salt(hex.encode(iv)));
  }

  /// Encrypts an hd wallet
  ///
  /// EncryptedWallet encryptedHdWallet = new WalletFactory().encryptWallet(wallet, password);
  EncryptedWallet encryptHdWallet(HdWallet wallet, String password) {
    String walletJson = json.encode(wallet);

    var key = _toSha256I(password);
    var iv = _toSha256I(walletJson).sublist(0, 16);
    CipherParameters params = new PaddedBlockCipherParameters(
        new ParametersWithIV(new KeyParameter(key as Uint8List), iv as Uint8List), null);

    BlockCipher encryptionCipher = new PaddedBlockCipher("AES/CBC/PKCS7");
    encryptionCipher.init(true, params);
    Uint8List encrypted = encryptionCipher.process(utf8.encode(walletJson) as Uint8List);
    String cipherText = hex.encode(encrypted);

    return EncryptedWallet(Source("flutter"), CipherText(cipherText),
        wallet.address, Salt(hex.encode(iv)));
  }

  /// Decrypts a basic wallet
  ///
  /// BasicWallet maybeWallet = new WalletFactory().decryptWallet(encryptedWallet, password);
  BasicWallet decryptWallet(EncryptedWallet wallet, String password) {
    var key = _toSha256I(password);
    var iv = hex.decode(wallet.salt.value!);
    var message = hex.decode(wallet.cipherText.value!);

    CipherParameters params = new PaddedBlockCipherParameters(
        new ParametersWithIV(new KeyParameter(key as Uint8List), iv as Uint8List), null);

    BlockCipher decryptionCipher = new PaddedBlockCipher("AES/CBC/PKCS7");
    decryptionCipher.init(false, params);
    String decrypted = utf8.decode(decryptionCipher.process(message as Uint8List));
    Map map = jsonDecode(decrypted);
    BasicWallet basicWallet = BasicWallet.fromJson(map as Map<String, dynamic>);
    return basicWallet;
  }

  /// Decrypts an hd wallet
  ///
  /// HdWallet hdWallet = new WalletFactory().decryptHdWallet(encryptedWallet, password);
  HdWallet decryptHdWallet(EncryptedWallet wallet, String password) {
    var key = _toSha256I(password);
    var iv = hex.decode(wallet.salt.value!);
    var message = hex.decode(wallet.cipherText.value!);

    CipherParameters params = new PaddedBlockCipherParameters(
        new ParametersWithIV(new KeyParameter(key as Uint8List), iv as Uint8List), null);

    BlockCipher decryptionCipher = new PaddedBlockCipher("AES/CBC/PKCS7");
    decryptionCipher.init(false, params);
    String decrypted = utf8.decode(decryptionCipher.process(message as Uint8List));
    Map map = jsonDecode(decrypted);
    HdWallet hdWallet = HdWallet.fromJson(map as Map<String, dynamic>);
    return hdWallet;
  }

  /// Gets the hexPrivateKey and the network from a wif
  ///
  /// NetworkPKey networkPrivateKey = new WalletFactory().getPrivateKeyAndNetworkFromWif(wif);
  NetworkPKey getPrivateKeyAndNetworkFromWif(Wif wif) {
    String decodedWif = _fromBase64(wif.value!);
    NetworkPrefix networkPrefix = NetworkPrefix(decodedWif.substring(0, 2));
    HexPrivateKey hexPrivateKey =
        HexPrivateKey(decodedWif.substring(2, decodedWif.length - 6));
    return new NetworkPKey(networkPrefix, hexPrivateKey);
  }

  /// Gets the hexPublicKey from the hexPrivateKey
  ///
  /// Future<HexPublicKey> hexPublicKey = await new WalletFactory().getPublicKeyFromPrivateKey(hexPrivateKey);
  Future<HexPublicKey> getPublicKeyFromPrivateKey(
      HexPrivateKey hexPrivateKey) async {
    var privateKeyBytes = hex.decode(hexPrivateKey.value!);
    return HexPublicKey(
        hex.encode(await ED25519_HD_KEY.getPublicKey(privateKeyBytes, false)));
  }

  String _toSha256(String message) {
    List<int> bytes = utf8.encode(message);
    return sha256.convert(bytes).toString();
  }

  List<int> _toSha256I(String message) {
    List<int> bytes = utf8.encode(message);
    return sha256.convert(bytes).bytes;
  }

  String _toBase64(String message) {
    List<int> bytes = utf8.encode(message);
    return base64.encode(bytes);
  }

  String _fromBase64(String message) {
    return utf8.decode(base64.decode(message));
  }

  String _toRipeMd160(String message) {
    List<int> bytes = utf8.encode(message);
    return _ripemd160Digest(bytes as Uint8List);
  }

  String _ripemd160Digest(Uint8List input) {
    RIPEMD160Digest digest = new RIPEMD160Digest();
    digest.update(input, 0, input.length);
    Uint8List result = new Uint8List(20);
    digest.doFinal(result, 0);
    return hex.encode(result);
  }
}
