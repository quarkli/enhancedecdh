import 'package:elliptic/elliptic.dart';
import 'package:elliptic/ecdh.dart';
import 'package:pointycastle/digests/ripemd160.dart';
import 'package:base_codecs/base_codecs.dart';
import 'package:encryptor/encryptor.dart';

var s256 = getS256(); // Get SECP256K1 curve object
void main(List<String> arguments) {
  // Create two key pairs, Alice and Bob
  PrivateKey alice = s256.generatePrivateKey();
  print('Alice\'s public key: ${alice.publicKey.toCompressedHex()}\n');
  PrivateKey bob = s256.generatePrivateKey();
  print('Bob\'s Public key: ${bob.publicKey.toCompressedHex()}\n');

  // Two participants example
  const msg = 'Hi, Bob!';

  var cipherMessage = encryptMessage(msg, alice, bob.publicKey);
  print('Ciphered Message:');
  print('$cipherMessage\n');

  print('Deciphered Messge: ');
  print('${decryptMessage(cipherMessage, bob)}\n');

  // One participant example
  const secret = 'my password';

  cipherMessage = encryptMessage(secret, alice);
  print('Ciphered Message:');
  print('$cipherMessage\n');

  print('Deciphered Messge: ');
  print('${decryptMessage(cipherMessage, alice)}\n');
}

Map encryptMessage(String msg, PrivateKey k, [PublicKey? otherPubkey]) {
  final encMsg = {};

  final nonce = s256.generatePrivateKey();
  encMsg['R'] = nonce.publicKey.toCompressedHex();

  final s = otherPubkey == null ? k.toHex() : computeSecretHex(k, otherPubkey);
  final h = hexEncode(RIPEMD160Digest().process(hexDecode(
      (BigInt.parse(s, radix: 16) + nonce.publicKey.X).toRadixString(16))));
  encMsg['H'] = h;

  final point = s256.add(
      s256.add(k.publicKey, nonce.publicKey), otherPubkey ?? k.publicKey);
  encMsg['P'] = PublicKey.fromPoint(s256, point).toCompressedHex();

  encMsg['C'] = Encryptor.encrypt(s + nonce.publicKey.toCompressedHex(), msg);
  return encMsg;
}

Map? decryptMessage(Map encMsg, PrivateKey k) {
  try {
    final nonce = PublicKey.fromHex(s256, encMsg['R']);
    final p = PublicKey.fromHex(s256, encMsg['P']);
    final sumPubkey = publicKeySubstract(p, nonce);
    if (sumPubkey == null) return null;

    final otherPubkey = publicKeySubstract(sumPubkey, k.publicKey);
    if (otherPubkey == null) return null;

    final s = otherPubkey == k.publicKey
        ? k.toHex()
        : computeSecretHex(k, otherPubkey);
    final h = hexEncode(RIPEMD160Digest().process(
        hexDecode((BigInt.parse(s, radix: 16) + nonce.X).toRadixString(16))));

    if (encMsg['H'] != h) {
      return null;
    }

    return {
      'M': Encryptor.decrypt(s + nonce.toCompressedHex(), encMsg['C']),
      'O': otherPubkey.toCompressedHex(),
    };
  } catch (e) {
    return null;
  }
}

PublicKey? publicKeySubstract(PublicKey p, PublicKey q) {
  final negQ = AffinePoint.fromXY(q.X, -q.Y);
  final r = s256.add(p, negQ);
  return s256.isOnCurve(r) ? PublicKey.fromPoint(s256, r) : null;
}
