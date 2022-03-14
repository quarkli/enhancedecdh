# Enhanced ECDH 
## Issues
ECDH proposed a method to calculate a shared key and encrypt/decrypt messages symmetrically using the shared key. However, the symmetric encryption/decryption produces a deterministic output which means the same content will always result in the same cipher with the same share key. This may expose some security risks.

Another issue with ECDH is the decryption process will also require the knowledge of the sender's public key to calculate the shared key. If the ciphered message was not directly exchanged between the two participants, the participants' public key information must be attached to the ciphered message to prompt the other participant which shared key to use. However, this will reveal the participants' identity or at least the relationship of the participants and the ciphered message.

## Summary
We propose an encryption/decryption method that the shared key is randomly generated every time and opaque data containing participant's information can be attached to the ciphered message such that only the participants can decrypt the message while none of the participant's information will be revealed. 

### Basic ECDH
1. Alice's key pair is A = aG, (Upper case A is public key; Lower case a is private key; G is the elliptic base point.)
2. Bob's key pair is B = bG
3. Alice's and Bob's shared key S = aB = bA = abG

### Enhanced ECDH encryption:
Assume Alice is generating an encrypted message that only Bob can decrypt.
1. Generate a temporary key R as a nonce
2. Calculate public key P, where P = A + B + R
3. Calculate an ECDH shared key S = aB
4. Calculate an actual shared key S' = R.x * S
5. Symmetrically encrypt the message with S' (AES) to get C
6. Calculate hash H = Hash(S')
7. Construct a ciphered message that contains (R, P, H, C)

### Enhanced ECDH decryption:
Bob gets the ciphered message (R, P, H, C)
1. Assume the other participant's public key is A = P - R - B
2. Calculate the ECDH shared key S = bA 
3. Assume the actual shared key S' = R.x * S
4. Evaluate Hash(S') == H
5. If Hash(S') == H, we have the correct S' and we can decrypt C with S' to get the plain text message and confirmed the other participant is Alice at the same time. 

The ciphered message (R, P, H, C) can be published/transmitted publicly. No one can decipher C without knowing the correct S'. 

R and S' are different every time, so even the participants are encrypting the same content, C will be different every time.

Nonce R and P provide no information of the participants and cannot be reverse calculated, except for the participants.

H is for a  checking purpose and can be omitted. Without H, the steps are the same, except the result is based on whether C can be decrypted without checking in advance. 


### Alternative usage
A user can encrypt a message to him/herself using the same method except replace ECDH S with his/her own private key.

### Implementation 
An example implementation has been written in Dart.

## Use cases
For example, a user may post an encrypted message on a public bulletin board or an open blockchain like Bitcoin. Everyone can see the encrypted message, but only the participants who hold the right keys can decrypt it without communication between both parties.