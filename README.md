# ✉ email-norm-fuzz

> Unicode Normalization Variant Generator for Bug Bounty Recon

**Author:** 0x0meowsec  
**Purpose:** Generate email normalization variants to detect account confusion,
username enumeration, and authentication bypass vulnerabilities.

---

## What It Does

Many authentication systems (Cognito, Auth0, Firebase, custom backends) handle
email normalization inconsistently across layers. This tool generates variants
of a given email address to help identify:

| Variant Type | Bug Class |
|---|---|
| Homoglyph substitution | Account confusion / shadow accounts |
| Unicode NFC/NFD/NFKC/NFKD | Normalization mismatch between app layers |
| Fullwidth ASCII | DB vs auth layer disagreement |
| Plus tag subaddressing | Uniqueness constraint bypass |
| Dot insertion | Gmail-style dot blindness |
| Whitespace / control chars | Input validation gaps |
| Encoding variants (`%40`, `@@`) | Parser confusion |
| Case variants | Case-sensitive vs insensitive pool mismatch |

---

## Install

```bash
git clone https://github.com/0x0meowsec/email-norm-fuzz
cd email-norm-fuzz
python3 email_norm_fuzz.py
```

No external dependencies — pure Python 3 stdlib only.

---

## Usage

```bash
python3 email_norm_fuzz.py
```

```
  Enter target email: victim@target.com

[+] Generated 143 variants for: victim@target.com

#     Label                                         Variant Email
────────────────────────────────────────────────────────────────────
1     uppercase_local                               VICTIM@target.com
2     homoglyph_pos0_v->U+FF56                     ｖictim@target.com
3     unicode_NFKC_local                            ...
...

  Save to file? (y/n): y
[+] Saved 143 variants to: victim_at_target_com_variants.txt
```

Output file is tab-separated: `label\tvariant_email` — pipe directly into your fuzzer.

---

## Real-World Test Flow

1. Register a test account on the target
2. Run this tool against your test email
3. Send `ForgotPassword` / `SignIn` with each variant
4. Compare responses — different behavior = normalization bug

**Signals to look for:**
- `CodeDeliveryDetails` returned for a variant → account resolved differently
- Password reset email arrives for a different account
- Duplicate account created with variant email
- Different error codes between canonical and variant

---

## Tested Against

- AWS Cognito (`ForgotPassword`, `SignUp`, `InitiateAuth`)
- Custom REST auth APIs
- OAuth2 / OIDC login flows

---

## Legal / Responsible Use

This tool is intended for **authorized security testing and bug bounty programs only**.

- Only test against targets you have **explicit written permission** to test
- Always follow the program's scope and rules
- Responsible disclosure before public reporting

The author is not responsible for misuse of this tool.
