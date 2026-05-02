import unicodedata
import os

def banner():
    print("""
╔══════════════════════════════════════════════╗
║                                              ║
║   ✉  email-norm-fuzz                         ║
║   Unicode Normalization Variant Generator    ║
║                                              ║
║Author : 0x0meowsec                           ║
║Purpose: Normalization attack on bug bounty   ║
║                                              ║
╚══════════════════════════════════════════════╝
    """)


def generate_variants(email: str) -> list[dict]:
    if "@" not in email:
        print("[-] Invalid email format.")
        return []

    local, domain = email.rsplit("@", 1)
    variants = []
    seen = set()

    def add(label, modified_local, modified_domain=domain):
        variant_email = f"{modified_local}@{modified_domain}"
        if variant_email not in seen:
            seen.add(variant_email)
            variants.append({"label": label, "email": variant_email})

    # --- 1. Case Variants ---
    add("uppercase_local", local.upper())
    add("titlecase_local", local.title())
    add("uppercase_domain", local, domain.upper())
    add("uppercase_all", local.upper(), domain.upper())

    # --- 2. Unicode Normalization Forms ---
    for form in ["NFC", "NFD", "NFKC", "NFKD"]:
        normalized_local = unicodedata.normalize(form, local)
        if normalized_local != local:
            add(f"unicode_{form}_local", normalized_local)
        normalized_domain = unicodedata.normalize(form, domain)
        if normalized_domain != domain:
            add(f"unicode_{form}_domain", local, normalized_domain)

    # --- 3. Homoglyph / Lookalike Characters ---
    HOMOGLYPHS = {
        'a': ['а', 'ａ', 'ä', 'à', 'á', 'â', 'ã'],
        'e': ['е', 'ｅ', 'ë', 'è', 'é', 'ê'],
        'o': ['о', 'ｏ', 'ö', 'ò', 'ó', 'ô', '0'],
        'i': ['і', 'ｉ', 'ï', 'ì', 'í', 'î', '1', 'l'],
        'l': ['ｌ', '1', 'I', 'і'],
        'c': ['с', 'ｃ'],
        'p': ['р', 'ｐ'],
        's': ['ѕ', 'ｓ'],
        'u': ['υ', 'ｕ'],
        'n': ['ｎ', 'η'],
        'm': ['ｍ'],
        'r': ['г', 'ｒ'],
        'x': ['х', 'ｘ'],
        't': ['ｔ'],
        'v': ['ν', 'ｖ'],
        'w': ['ｗ', 'ω'],
        'g': ['ｇ'],
        'k': ['κ', 'ｋ'],
        'y': ['у', 'ｙ'],
        'b': ['ｂ', 'β'],
        'f': ['ｆ'],
        'h': ['ｈ', 'η'],
        'z': ['ｚ'],
        'd': ['ｄ'],
        'j': ['ｊ'],
        'q': ['ｑ'],
    }

    for i, char in enumerate(local):
        if char.lower() in HOMOGLYPHS:
            for glyph in HOMOGLYPHS[char.lower()]:
                mutated = local[:i] + glyph + local[i+1:]
                add(f"homoglyph_pos{i}_{char}->U+{ord(glyph):04X}", mutated)

    # --- 4. Fullwidth ASCII ---
    def to_fullwidth(s):
        result = ""
        for c in s:
            cp = ord(c)
            if 0x21 <= cp <= 0x7E:
                result += chr(cp + 0xFEE0)
            elif c == ' ':
                result += '\u3000'
            else:
                result += c
        return result

    add("fullwidth_local", to_fullwidth(local))
    add("fullwidth_domain", local, to_fullwidth(domain))

    # --- 5. Subaddressing / Plus Tags ---
    for tag in ["test", "admin", "bugbounty", "noreply", "info", "support"]:
        add(f"plus_tag_{tag}", f"{local}+{tag}")

    # --- 6. Dot Manipulation ---
    add("trailing_dot_domain", local, domain + ".")
    for i in range(1, len(local)):
        if local[i-1] != '.' and local[i] != '.':
            add(f"dot_insert_pos{i}", local[:i] + '.' + local[i:])

    # --- 7. Whitespace / Control Chars (validator behavior testing) ---
    add("trailing_space_local", local + " ")
    add("leading_space_local", " " + local)
    add("tab_in_local", local[:2] + "\t" + local[2:])
    add("null_byte_local", local + "\x00")
    add("carriage_return", local + "\r")

    # --- 8. Domain Variants ---
    add("domain_punycode_prefix", local, "xn--" + domain)
    parts = domain.split(".")
    if len(parts) >= 2:
        add("subdomain_inject", local, "attacker.com." + domain)

    # --- 9. Encoding Variants ---
    add("url_encoded_at", local + "%40" + domain, "")
    add("double_at", local + "@@" + domain, "")
    add("quoted_local", f'"{local}"')

    return variants


def print_variants(email: str) -> list[dict]:
    variants = generate_variants(email)
    if not variants:
        return []

    print(f"\n[+] Generated {len(variants)} variants for: {email}\n")
    print(f"{'#':<5} {'Label':<45} {'Variant Email'}")
    print("─" * 100)
    for i, v in enumerate(variants, 1):
        print(f"{i:<5} {v['label']:<45} {v['email']}")
    return variants


def save_variants(email: str, variants: list[dict]):
    filename = email.replace("@", "_at_").replace(".", "_") + "_variants.txt"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(f"# email-norm-fuzz | Author: 0x0meowsec\n")
        f.write(f"# Target: {email}\n")
        f.write(f"# Total variants: {len(variants)}\n\n")
        for v in variants:
            f.write(f"{v['label']}\t{v['email']}\n")
    print(f"\n[+] Saved {len(variants)} variants to: {filename}")


if __name__ == "__main__":
    banner()
    email = input("  Enter target email: ").strip()
    variants = print_variants(email)

    if variants:
        save = input("\n  Save to file? (y/n): ").strip().lower()
        if save == "y":
            save_variants(email, variants)

    print("\n  [!] Use only on targets you have explicit permission to test.\n")
