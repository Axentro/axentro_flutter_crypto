# Axentro Crypto for Flutter

A Flutter plugin for iOS and Android providing the base crypto functions for the [Axentro](https://axentro.io) blockchain platform.

## Features

* generateKeyPair
* generateNewWallet
* generateWif
* generateAddress
* getWalletFromWif
* getFullWalletFromWif
* encryptWallet
* decryptWallet

## Installation

Add the dependency to your `pubspec.yaml`

```yaml
dependencies:
  axentro: ^0.0.1
```

## Example

```dart
import 'package:dartz/dartz.dart';
import 'package:axentro/network.dart';
import 'package:axentro/wallet_factory.dart';

walletFactory.generateNewWallet(Network.testnet).fold(handleErrorHere,(basicWallet){
  // Do something with the basicWallet here
});
```