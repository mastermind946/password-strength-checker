# Password Strength Checker

A beginner-friendly command-line tool that rates how strong a password is, gives tips for improving it, and checks whether it has appeared in a known data breach, **without ever sending the password anywhere**.

Built as a cybersecurity learning project using only the Python standard library.

## Features

- **Strength rating:** Weak, Moderate or Strong
- **Length report:** number of characters
- **Breach check:** looks the password up in the [Have I Been Pwned](https://haveibeenpwned.com/Passwords) database using a privacy-preserving method (see below)
- **Improvement tips:** specific advice for each problem found
- **Detects:**
  - Short passwords
  - Missing character types (lowercase, uppercase, numbers, symbols)
  - Common passwords, including disguised ones like `P@ssw0rd!` and `Password123!`
  - Predictable sequences such as `abcd`, `4321` and `qwer`
  - Repeated characters such as `aaaa`
  - Personal info (your name or username) inside the password
- **Secure password generator** using Python's `secrets` module
- **Hidden input:** what you type is never shown on screen
- **No dependencies:** just Python

## Quick start

```bash
git clone https://github.com/YOUR_USERNAME/password-strength-checker.git
cd password-strength-checker
python password_checker.py
```

Requires Python 3.9 or newer. An internet connection is needed only for the breach check.

## Usage

When the program starts you can optionally enter your name or username (comma separated) so it can make sure they aren't in your password. Then:

| Input | What it does |
|---|---|
| *any password* | Analyzes it (typing is hidden) |
| `gen` | Generates a strong random password |
| `exit` | Quits |

### Example output

```
----------------------------------------------
  Strength : Moderate
  Length   : 10 characters
  Breached : NO, not found in known breaches
----------------------------------------------
  Tips for improvement:
   - Make it at least 12 characters (16+ is even better).
   - Add symbols such as ! @ # $.
   - Avoid predictable sequences like 'abcd'.
----------------------------------------------
```

If the password has leaked, the report shows how often:

```
  Breached : YES, found 3,730,471 times in known breaches
```

If you're offline, it shows `UNKNOWN` instead of a false "NO", and adds a tip to re-check later.

## How strength is decided

| Rating | Conditions |
|---|---|
| **Weak** | Under 8 characters, **or** a common password, **or** found in a breach, **or** under 12 characters with fewer than 3 character types |
| **Moderate** | Has a sequence, repeats or personal info, **or** is under 12 characters, **or** uses fewer than 3 character types |
| **Strong** | 12+ characters, 3 or more character types, and none of the red flags above |

A breached password is always **Weak**, no matter how complex it looks, because once it is public an attacker can simply try it.

## How the breach check protects your privacy

Your password is **never** sent over the network. The tool uses the *k-anonymity* technique offered by the Have I Been Pwned API:

1. The password is hashed locally with SHA-1.
2. Only the **first 5 characters** of that hash are sent to the API.
3. The API replies with every leaked hash that starts with those 5 characters (hundreds of them).
4. The tool searches that list **locally** for the rest of your hash.

This tool also never writes passwords to disk, logs them or prints them back.

## Limitations

- The built-in list of common passwords is small (about 35 entries). Real attackers use lists with millions. Extending `COMMON_PASSWORDS` or loading a larger wordlist is an easy improvement.
- Strength rules are simple heuristics. They don't model dictionary words, names or dates the way advanced estimators like [zxcvbn] do. A long passphrase of ordinary words is rated Moderate rather than Strong.
- The breach check depends on a third-party service being reachable.

## Disclaimer

This is an educational project. A "Strong" rating is an estimate, not a guarantee. For real accounts, use a password manager, give every account a unique password, and turn on two-factor authentication.

## License

Released under the MIT License.