# PwdGen

A terminal password generator for macOS, built in C with ncurses.

## Build

```sh
make
./passgen
```

`make` downloads the EFF large Diceware wordlist as `eff_large_wordlist.txt`, then builds with `-Wall -Wextra` and links ncurses.

## Keybindings

- Password mode: `Left` / `Right` or `-` / `+` adjusts character length from 1 to 128
- Password mode: `[` / `]` adjusts character length in larger 8-character steps
- Passphrase mode: `Left` / `Right` or `-` / `+` adjusts the number of words from 1 to 32
- Passphrase mode: `[` / `]` adjusts the number of words in 2-word steps
- Passphrase mode: `T` cycles separators between hyphens, spaces, and none
- `U`: toggle uppercase letters
- `L`: toggle lowercase letters
- `D`: toggle digits
- `S`: toggle symbols
- `M`: switch between password and Diceware passphrase mode
- `Space` / `Enter`: regenerate
- `V`: show or hide the generated output; output is hidden by default
- `C`: copy the current output to the macOS clipboard with `pbcopy`
- `h`: show or hide only the latest history item
- `H`: show or hide the full session history
- When full history is visible: `Up` / `Down` scroll by one item
- When full history is visible: `PageUp` / `PageDown` scroll by a page
- `Q` / `Escape`: exit

Generated history is hidden by default, kept only in memory for the current session, capped at 100 entries, and cleared on exit.
