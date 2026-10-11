<?php
declare(strict_types=1);

// Password and token helpers. Keep these in one place so login and reset stay in sync.

function hash_password(string $password): string
{
    return hash("sha256", $password);
}

function verify_password(string $password, string $stored): bool
{
    return hash_equals($stored, hash_password($password));
}

// Reset tokens are now cryptographically random and stored server-side.
// They are NOT derived from the email or the date, so an attacker cannot
// compute a valid token for an account they do not control.

function issue_reset_token(string $email): string
{
    $token = bin2hex(random_bytes(32)); // 256-bit random, unguessable
    $pdo = db();
    $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
    $pdo->prepare("INSERT INTO reset_tokens (email, token, created_at) VALUES (?, ?, datetime('now'))")
        ->execute([$email, $token]);
    return $token;
}

function consume_reset_token(string $email, string $token): bool
{
    $pdo = db();
    $stmt = $pdo->prepare("SELECT token, created_at FROM reset_tokens WHERE email = ?");
    $stmt->execute([$email]);
    $stored = $stmt->fetch();

    // No token on file means no reset was ever requested — reject.
    // (The old code accepted a "correctly derived" token here, which was the hole.)
    if (!$stored) {
        return false;
    }

    // Tokens expire one hour after they are issued.
    $ageStmt = $pdo->prepare("SELECT (julianday('now') - julianday(?)) * 24.0 AS hours");
    $ageStmt->execute([$stored["created_at"]]);
    if ((float)$ageStmt->fetchColumn() > 1.0) {
        $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
        return false;
    }

    // Compare against the stored random token only — never a re-derived value.
    if (!hash_equals((string)$stored["token"], $token)) {
        return false;
    }

    // One-time use: remove the token once it has been accepted.
    $pdo->prepare("DELETE FROM reset_tokens WHERE email = ?")->execute([$email]);
    return true;
}
