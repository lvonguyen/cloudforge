# Git Commit Signing with 1Password

Configure Git to sign commits using SSH keys stored in 1Password.

---

## [>] Prerequisites

1. 1Password desktop app installed
2. 1Password CLI (`op`) installed
3. SSH key stored in 1Password

---

## [+] Setup Steps

### 1. Enable 1Password SSH Agent

**1Password -> Settings -> Developer**

- [x] Use the SSH agent
- [x] Enable SSH key storage

### 2. Configure Git to Use 1Password for Signing

```bash
# Set signing format to SSH
git config --global gpg.format ssh

# Point to 1Password SSH agent
git config --global gpg.ssh.program "/Applications/1Password.app/Contents/MacOS/op-ssh-sign"

# Set your signing key (from 1Password)
git config --global user.signingkey "ssh-ed25519 AAAAC3Nza..."

# Enable auto-signing
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

### 3. Get Your Signing Key from 1Password

```bash
# List SSH keys in 1Password
op item list --categories "SSH Key"

# Get public key
op read "op://Personal/SSH Key/public key"
```

### 4. Add Signing Key to GitHub/GitLab

**GitHub:**
1. Settings -> SSH and GPG keys -> New SSH key
2. Key type: **Signing Key**
3. Paste public key

**GitLab:**
1. Preferences -> SSH Keys
2. Usage type: **Signing** (or Authentication & Signing)
3. Paste public key

---

## [/] Configuration Files

### ~/.gitconfig

```ini
[user]
    name = Liem Vo-Nguyen
    email = liem@vonguyen.io
    signingkey = ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...

[gpg]
    format = ssh

[gpg "ssh"]
    program = /Applications/1Password.app/Contents/MacOS/op-ssh-sign
    allowedSignersFile = ~/.ssh/allowed_signers

[commit]
    gpgsign = true

[tag]
    gpgsign = true
```

### ~/.ssh/allowed_signers

For verifying signatures locally:

```
liem@vonguyen.io ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
```

---

## [+] Verification

### Check Signing Works

```bash
# Create test commit
echo "test" > test.txt
git add test.txt
git commit -m "test: Verify commit signing"

# Verify signature
git log --show-signature -1
```

Expected output:
```
Good "git" signature for liem@vonguyen.io with ED25519 key SHA256:...
```

### Check on GitHub/GitLab

Commits should show **Verified** badge.

---

## [!] Troubleshooting

| Issue | Cause | Solution |
|-------|-------|----------|
| `error: cannot sign commit` | 1Password locked | Unlock 1Password app |
| `key not found` | Wrong key reference | Check `user.signingkey` |
| `bad signature` | Key mismatch | Re-add signing key to platform |
| `op-ssh-sign not found` | Wrong path | Verify 1Password installation path |

### Linux Path

```bash
git config --global gpg.ssh.program "/opt/1Password/op-ssh-sign"
```

### Verify 1Password Agent

```bash
# Check agent socket
echo $SSH_AUTH_SOCK
# Should be: ~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock

# Test connection
ssh-add -l
```

---

## [>] One-Liner Setup

```bash
# Full setup (macOS)
git config --global gpg.format ssh && \
git config --global gpg.ssh.program "/Applications/1Password.app/Contents/MacOS/op-ssh-sign" && \
git config --global user.signingkey "$(op read 'op://Personal/SSH Key/public key')" && \
git config --global commit.gpgsign true && \
git config --global tag.gpgsign true && \
echo "$(git config user.email) $(op read 'op://Personal/SSH Key/public key')" >> ~/.ssh/allowed_signers
```

---

## [+] Per-Context Signing Keys

If you have different keys for Personal vs Work:

```bash
# ~/.gitconfig
[includeIf "gitdir:~/repos/remote/gh/"]
    path = ~/.gitconfig-personal

[includeIf "gitdir:~/repos/remote/gl/lvonguyen/"]
    path = ~/.gitconfig-personal

[includeIf "gitdir:~/repos/remote/gl/haea/"]
    path = ~/.gitconfig-haea
```

```bash
# ~/.gitconfig-personal
[user]
    email = liem@vonguyen.io
    signingkey = ssh-ed25519 AAAA... # Personal key

# ~/.gitconfig-haea
[user]
    email = liem.vo-nguyen@haea.com
    signingkey = ssh-ed25519 BBBB... # Work key
```
