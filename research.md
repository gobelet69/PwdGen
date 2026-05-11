# Cryptographically Secure Password Generation Research

## Scope

This document summarizes current implementation guidance for a local C password generator targeting macOS terminals, with portability notes for Linux. The design goal is unpredictable output suitable for account passwords and passphrases, generated locally from operating-system cryptographic random APIs.

## CSPRNG APIs on macOS and Linux

### macOS

For application code on macOS, prefer `arc4random_buf()` for random bytes and `arc4random_uniform()` or rejection sampling for bounded integers. Apple's archived `arc4random(3)` page documents automatic initialization and says there is no need to call `arc4random_stir()` before use because `arc4random()` initializes itself. OpenBSD's current `arc4random(3)` manual is clearer about modern behavior: the family is preferred over `rand(3)`, `random(3)`, and `rand48(3)`, uses a cryptographic PRNG, reseeds from the kernel via `getentropy(2)`, and `arc4random_uniform()` avoids modulo bias.

`getentropy()` is available on macOS 10.12 and later. Its macOS manual describes it as a direct kernel random byte API, limited to 256 bytes per call, and primarily intended for seeding process-context PRNGs. For callers that simply need random bytes, that same page recommends `arc4random(3)`, CommonCrypto random bytes, or `SecRandomCopyBytes()` instead of direct `getentropy()`.

`SecRandomCopyBytes(kSecRandomDefault, count, buf)` is Apple's Security framework API for security-sensitive random bytes. It is appropriate when an application already links Security.framework or wants the framework-level API. For a small C terminal utility, `arc4random_buf()` avoids extra framework linkage and is available from libc.

### Linux

Linux provides `/dev/urandom`, `/dev/random`, `getrandom(2)`, and glibc `getentropy(3)`. The Linux `random(7)` manual says the kernel RNG gathers entropy from device drivers and environmental noise to seed a CSPRNG. It recommends using `/dev/urandom` or `getrandom()` without `GRND_RANDOM` for almost all purposes, warning that `/dev/random` and `GRND_RANDOM` can block indefinitely and complicate reads.

`getrandom(2)` without flags reads from the same source as `/dev/urandom` and blocks during early boot until the entropy pool is initialized. The man page recommends small `getrandom()` reads of 256 bytes or less from the urandom source; glibc's `getentropy()` provides a portable wrapper with that 256-byte model.

## Entropy Sources and Randomness

Modern operating systems collect entropy from interrupts, device timing, hardware random sources, boot-time seeds, disk/network/input timings, and CPU jitter or hardware RNG instructions where available. Application code should not attempt to estimate or improve entropy manually with timestamps, process IDs, pointer values, or user keystroke timing. The correct pattern is:

1. Use the OS CSPRNG API directly.
2. Avoid deterministic or low-entropy seeds.
3. Avoid modulo bias when mapping random bytes to character indices or word indices.
4. Treat hardware entropy as an OS concern unless building kernel or platform RNG infrastructure.

For this project, random bytes are generated with `arc4random_buf()` and mixed with small `getentropy()` reads when available. Bounded selections use rejection sampling so every character or word index is uniformly likely.

## Diceware and the EFF Large Wordlist

Diceware-style passphrases choose words independently and uniformly from a fixed wordlist. EFF's long wordlist contains 7,776 words, matching `6^5`, so each word corresponds to five six-sided dice rolls. EFF states that the long list is suitable for five dice and that a six-word passphrase from this list provides about 77 bits of entropy. Each additional word adds about 12.9 bits because `log2(7776) = log2(6^5)`.

Implementation notes:

- Load the EFF large wordlist as data, not as a password history file.
- Select word indices uniformly over `[0, 7775]`.
- Join words with a separator such as `-` for readability.
- Entropy is `word_count * log2(7776)`, assuming independent uniform word choices.

## Password Entropy Calculation

For uniformly generated passwords where each character is independently selected from a pool of size `N`, entropy is:

```text
H = L * log2(N)
```

Where:

- `H` is entropy in bits.
- `L` is password length.
- `N` is the active character pool size.

Example pool sizes:

- Lowercase only: 26
- Uppercase + lowercase: 52
- Alphanumeric: 62
- Uppercase + lowercase + digits + common symbols: depends on symbol set; this tool uses 88 total characters when all built-in sets are enabled.

Practical thresholds vary by threat model. A reasonable local meter can treat values below 50 bits as weak, 50-79 bits as moderate, and 80+ bits as strong for randomly generated online-account passwords. Higher values are better for secrets exposed to offline guessing, high-value accounts, or long-lived credentials.

## NIST and Industry Recommendations

NIST SP 800-63B-4, published July 2025, emphasizes length and usability over composition rules. It states that verifiers and CSPs shall not impose password composition rules, shall not require periodic password changes absent compromise, and should support long passwords and passphrases. Its usability section says systems should allow at least 64 characters, encourage users to make passwords as long as they want, allow any characters including spaces, and support copy/paste and autofill for password managers.

For generated passwords, composition toggles can be useful to satisfy legacy sites. They should not be presented as intrinsically better than length. A generator should support long outputs, printable characters, and passphrases, while making entropy visible.

The requested 14-16+ character visual highlight is aligned with modern industry practice: randomly generated passwords of 14 or more characters from a broad pool are strong for most online uses, and longer passwords or passphrases improve margin.

## Weaknesses to Avoid

- Do not use `rand()`, `random()`, `drand48()`, or `srand(time(NULL))` for passwords. CERT C rule MSC30-C warns not to use `rand()` for security-sensitive pseudorandom numbers.
- Do not seed a PRNG with time, PID, hostname, or similar predictable values.
- Do not use `random_byte % n` unless `n` divides the byte or integer range; use rejection sampling or `arc4random_uniform()`.
- Do not write generated passwords or session history to disk.
- Do not silently fall back to a weak PRNG if the OS CSPRNG fails.
- Do not require arbitrary composition rules for user-chosen passwords; offer character set toggles only for compatibility with site constraints.

## Sources

- NIST, [SP 800-63B-4 Digital Identity Guidelines: Authentication and Authenticator Management](https://tsapps.nist.gov/publication/get_pdf.cfm?pub_id=959882), July 2025.
- Linux man-pages, [random(7)](https://man7.org/linux/man-pages/man7/random.7.html).
- Linux man-pages, [getrandom(2)](https://man7.org/linux/man-pages/man2/getrandom.2.html).
- Apple Developer Documentation Archive, [Mac OS X Manual Page for arc4random(3)](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/arc4random.3.html).
- OpenBSD manual pages, [arc4random(3)](https://man.openbsd.org/arc4random.3).
- OpenBSD manual pages, [getentropy(2)](https://man.openbsd.org/getentropy.2).
- Unix.com mirror of macOS Mojave manual, [getentropy(2)](https://www.unix.com/man_page/mojave/2/getentropy/).
- Apple Developer Documentation, [SecRandomCopyBytes](https://developer.apple.com/documentation/security/secrandomcopybytes%28_%3A_%3A_%3A%29).
- Electronic Frontier Foundation, [Dice-Generated Passphrases](https://www.eff.org/dice).
- Electronic Frontier Foundation, [EFF's New Wordlists for Random Passphrases](https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases).
- SEI CERT C Coding Standard, [MSC30-C: Do not use the rand() function for generating pseudorandom numbers](https://wiki.sei.cmu.edu/confluence/display/c/MSC30-C.%2BDo%2Bnot%2Buse%2Bthe%2Brand%28%29%2Bfunction%2Bfor%2Bgenerating%2Bpseudorandom%2Bnumbers).
