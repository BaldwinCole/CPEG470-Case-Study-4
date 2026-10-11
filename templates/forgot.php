<section class="narrow">
  <h1>Reset a password</h1>
  <p class="lede">We email a one-time reset token to your campus address. Open the reset form from that message to choose a new password.</p>
  <?php if (!empty($notice)): ?><p class="flash ok"><?= e($notice) ?></p><?php endif; ?>
  <form method="post" action="/forgot" class="stack">
    <label><span>Email</span><input type="email" name="email" required></label>
    <button type="submit">Request reset</button>
  </form>
  <p class="lede"><a href="/reset">I already have a token</a></p>
</section>
