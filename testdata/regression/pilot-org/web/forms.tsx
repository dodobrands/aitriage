export function SignupForm() {
  return (
    <form>
      <input name="name" placeholder="Your name" />
      <input name="email" placeholder="Email address" />
      <input name="phone" placeholder="Phone number" />
      <input name="city" placeholder="City" />
      <input name="street" placeholder="Street" />
      <input name="zip" placeholder="Postal code" />
      <textarea name="note" placeholder="Anything we should know?" />
    </form>
  );
}
