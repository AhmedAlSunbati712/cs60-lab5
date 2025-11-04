"""
break_encryption.py     Ahmed Al Sunbati       Nov 3rd, 2025
Description: Interactive tool for breaking monoalphabetic substitution ciphers. Supports
             frequency analysis, manual mapping of cipher letters to plaintext, and
             live preview of partial decryption.
usage: 

Citations: GeminiAI to help style the UI of the interactive loop (in the interactive_loop function)
           and for also refactoring the code.
"""
import sys
from collections import defaultdict, Counter
import string

# English letters ranked by frequency (most frequent to least frequent)
letters_sorted = list("etaoinshrdlcumwfgypbvkjxqz")

def read_cipher(path):
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()

def count_letters(text):
    c = Counter(ch for ch in text if ch.isalpha())
    return c

def seed_mapping_by_freq(counter):
    # Return a dict cipher->plaintext by frequency guess
    # Most frequent ciphertext char -> 'e', second -> 't', etc.
    cipher_by_freq = [p[0] for p in counter.most_common()]
    mapping = {}
    for i, cipher_char in enumerate(cipher_by_freq):
        if i < len(letters_sorted):
            mapping[cipher_char] = letters_sorted[i]
    return mapping

def apply_mapping(text, mapping):
    # Show replaced plaintext letters in UPPERCASE so user can see them
    out = []
    for ch in text:
        if ch.isalpha():
            # preserve case of original only in non-replaced letters:
            if ch in mapping:
                out.append(mapping[ch].upper())   # replaced -> show uppercase plaintext
            else:
                out.append(ch.lower())           # still ciphertext -> lowercase
        else:
            out.append(ch)
    return ''.join(out)

def parse_assignment(s):
    """
    Accept assignments like:
      h=E
      ylh=THE
      a=b
    Returns list of (cipher_char, plaintext_char)
    """
    s = s.strip()
    if '=' not in s:
        return None
    left, right = s.split('=', 1)
    left = left.strip()
    right = right.strip()
    # Normalize: treat uppercase right-side as plaintext letters (we'll store them lowercase)
    if len(left) != len(right):
        # allow repeating single-letter RHS if user typed single char
        if len(right) == 1:
            right = right * len(left)
        else:
            return None
    pairs = []
    for c, p in zip(left, right):
        if not c.isalpha() or not p.isalpha():
            return None
        pairs.append((c.lower(), p.lower()))
    return pairs

def interactive_loop(text, mapping):
    print("\n=== Partial decode (UPPERCASE = plaintext you've fixed) ===\n")
    print(apply_mapping(text, mapping))
    print("\nCommands:")
    print("  <pair>    For example:  h=E   or  ylh=THE   (left side ciphertext letters, right side plaintext letters)")
    print("  freq      show letter frequency counts")
    print("  seed      seed mapping by frequency (most->'e', next->'t', ...)")
    print("  clear     clear mapping")
    print("  save NAME save current decoded output to file NAME")
    print("  quit      exit\n")

    while True:
        cmd = input("map> ").strip()
        if not cmd:
            continue
        if cmd.lower() in ('q', 'quit', 'exit'):
            print("bye")
            break
        if cmd.lower() == 'freq':
            c = count_letters(text)
            for ch, n in c.most_common():
                print(f"{ch}: {n}")
            continue
        if cmd.lower() == 'seed':
            mapping.clear()
            mapping.update(seed_mapping_by_freq(count_letters(text)))
            print("seeded mapping (most-freq->etaoin...)")
            print(apply_mapping(text, mapping))
            continue
        if cmd.lower() == 'clear':
            mapping.clear()
            print("mapping cleared")
            print(apply_mapping(text, mapping))
            continue
        if cmd.lower().startswith('save '):
            _, fname = cmd.split(' ', 1)
            out = apply_mapping(text, mapping)
            with open(fname.strip(), 'w', encoding='utf-8') as f:
                f.write(out)
            print(f"saved to {fname.strip()}")
            continue

        parsed = parse_assignment(cmd)
        if parsed is None:
            print("unrecognized assignment. Examples: h=E   or   ylh=THE")
            continue
        # apply pairs
        for c, p in parsed:
            mapping[c] = p  # cipher->plaintext (lowercase)
        print("\n" + apply_mapping(text, mapping) + "\n")

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 sub_decoder.py cipher.txt")
        sys.exit(1)
    path = sys.argv[1]
    text = read_cipher(path)
    initial_map = {}
    interactive_loop(text, initial_map)

if __name__ == '__main__':
    main()
