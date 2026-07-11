# Authentication follow-up

Email confirmation is temporarily disabled in the Chat2 Supabase project so
registration does not depend on the free shared email rate limit.

Before opening registration to the public:

1. Configure a custom SMTP provider in Supabase Auth.
2. Customize and test the confirmation and resend-email templates.
3. Re-enable **Authentication → Sign In / Providers → Confirm email**.
4. Verify registration, confirmation, resend, login, logout, and password reset.
5. Update the frontend message that currently allows immediate login after signup.

