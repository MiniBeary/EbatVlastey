# Third-party notices

The published self-contained application includes the Microsoft .NET runtime (MIT and component notices) and BouncyCastle.Cryptography 2.7.0 (MIT).

- .NET: https://github.com/dotnet/runtime/blob/main/LICENSE.TXT and https://github.com/dotnet/runtime/blob/main/THIRD-PARTY-NOTICES.TXT
- Bouncy Castle: https://github.com/bcgit/bc-csharp/blob/master/LICENSE.md; the complete license is included in docs/bouncycastle-license.txt.

Bouncy Castle is used only by the local verification TLS server because Windows Schannel does not accept the chosen ephemeral server keys on the tested build. Certificate generation and Windows trust operations use .NET and CryptoAPI.
