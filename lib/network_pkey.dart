import 'model.dart';

/// This holds an network and private key
/// * network
/// * hexPrivateKey
class NetworkPKey {
  NetworkPrefix? _networkPrefix;
  HexPrivateKey? _hexPrivateKey;

  NetworkPKey(NetworkPrefix _networkPrefix, HexPrivateKey hexPrivateKey) {
    this._networkPrefix = _networkPrefix;
    this._hexPrivateKey = hexPrivateKey;
  }

  /// Returns the network
  NetworkPrefix? get networkPrefix {
    return _networkPrefix;
  }

  /// Returns the privateKey in hex format
  HexPrivateKey? get hexPrivateKey {
    return _hexPrivateKey;
  }
}
