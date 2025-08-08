from password_checker import PasswordAnalyzer
import getpass


def display_results(results):
    """Display analysis results in a user-friendly format"""
    print("\n" + "=" * 50)
    print("PASSWORD SECURITY ANALYSIS REPORT")
    print("=" * 50)

    print(f"Password Strength: {results['strength']} ({results['score']}/100)")
    print(f"Entropy: {results['entropy']:.2f} bits")

    print("\nSECURITY CHECKS:")
    print(f"✓ Length (8+ chars): {'PASS' if results['length_ok'] else 'FAIL'}")

    complexity = results['complexity']
    print(f"✓ Uppercase letters: {'PASS' if complexity['uppercase'] else 'FAIL'}")
    print(f"✓ Lowercase letters: {'PASS' if complexity['lowercase'] else 'FAIL'}")
    print(f"✓ Numbers: {'PASS' if complexity['digits'] else 'FAIL'}")
    print(f"✓ Special characters: {'PASS' if complexity['special_chars'] else 'FAIL'}")

    patterns = results['weak_patterns']
    print(f"✓ No sequential numbers: {'PASS' if not patterns['sequential_numbers'] else 'FAIL'}")
    print(f"✓ No keyboard patterns: {'PASS' if not patterns['keyboard_patterns'] else 'FAIL'}")
    print(f"✓ No repeated characters: {'PASS' if not patterns['repeated_chars'] else 'FAIL'}")
    print(f"✓ Not common password: {'PASS' if not results['is_common'] else 'FAIL'}")

    print(f"\nPassword Hash (SHA-256): {results['hash'][:32]}...")

    # Provide recommendations
    print("\nRECOMMENDATIONS:")
    if results['score'] < 70:
        if not results['length_ok']:
            print("• Use at least 8 characters")
        if not complexity['uppercase']:
            print("• Add uppercase letters")
        if not complexity['lowercase']:
            print("• Add lowercase letters")
        if not complexity['digits']:
            print("• Add numbers")
        if not complexity['special_chars']:
            print("• Add special characters (!@#$%^&*)")
        if patterns['sequential_numbers']:
            print("• Avoid sequential numbers (123, 456, etc.)")
        if patterns['keyboard_patterns']:
            print("• Avoid keyboard patterns (qwerty, asdf, etc.)")
        if results['is_common']:
            print("• Avoid common passwords")
    else:
        print("• Great job! Your password meets security standards.")

    print("=" * 50)


def main():
    analyzer = PasswordAnalyzer()

    print("Password Security Analyzer & Generator")
    print("This tool will analyze password strength and generate secure passwords.")
    print("Note: Your passwords are not stored or transmitted.\n")

    while True:
        print("\nOptions:")
        print("1. Analyze a password")
        print("2. Generate secure passwords")
        print("3. Generate passphrase")
        print("4. Learn about password security")
        print("5. Exit")

        choice = input("\nEnter your choice (1-5): ").strip()

        if choice == '1':
            # Existing password analysis code
            password = getpass.getpass("Enter password to analyze (hidden): ")
            if password:
                results = analyzer.analyze_password(password)
                display_results(results)
            else:
                print("Please enter a password.")

        elif choice == '2':
            generate_passwords_menu(analyzer)

        elif choice == '3':
            generate_passphrase_menu(analyzer)

        elif choice == '4':
            show_security_tips()

        elif choice == '5':
            print("Thanks for using Password Security Analyzer!")
            break

        else:
            print("Invalid choice. Please try again.")


def generate_passwords_menu(analyzer):
    """Interactive password generation menu"""
    print("\n" + "=" * 50)
    print("SECURE PASSWORD GENERATOR")
    print("=" * 50)

    # Get user preferences
    try:
        length = int(input("Password length (8-128, default 16): ") or "16")
        if length < 8 or length > 128:
            length = 16
            print("Using default length of 16")
    except ValueError:
        length = 16
        print("Using default length of 16")

    print("\nCharacter types to include:")
    include_upper = input("Include uppercase letters? (Y/n): ").lower() != 'n'
    include_lower = input("Include lowercase letters? (Y/n): ").lower() != 'n'
    include_digits = input("Include numbers? (Y/n): ").lower() != 'n'
    include_symbols = input("Include symbols? (Y/n): ").lower() != 'n'
    exclude_ambiguous = input("Exclude ambiguous characters (0,O,1,l,I)? (Y/n): ").lower() != 'n'

    try:
        count = int(input("How many passwords to generate? (1-10, default 5): ") or "5")
        if count < 1 or count > 10:
            count = 5
    except ValueError:
        count = 5

    print(f"\nGenerating {count} secure passwords...\n")

    # Generate passwords
    for i in range(count):
        try:
            password = analyzer.generate_secure_password(
                length=length,
                include_uppercase=include_upper,
                include_lowercase=include_lower,
                include_digits=include_digits,
                include_symbols=include_symbols,
                exclude_ambiguous=exclude_ambiguous
            )

            # Analyze the generated password
            analysis = analyzer.analyze_password(password)

            print(f"Password {i + 1}: {password}")
            print(f"Strength: {analysis['strength']} ({analysis['score']}/100)")
            print(f"Entropy: {analysis['entropy']:.1f} bits")
            print("-" * 40)

        except ValueError as e:
            print(f"Error generating password: {e}")
            break

    # Offer to analyze one of the generated passwords
    choice = input("\nWould you like to analyze one of these passwords in detail? (y/N): ")
    if choice.lower() == 'y':
        try:
            num = int(input(f"Which password (1-{count})? ")) - 1
            if 0 <= num < count:
                # You'd need to store the passwords to do this analysis
                print("Feature coming soon - for now, copy and paste the password into option 1!")
        except ValueError:
            print("Invalid selection")


def generate_passphrase_menu(analyzer):
    """Interactive passphrase generation menu"""
    print("\n" + "=" * 50)
    print("PASSPHRASE GENERATOR")
    print("=" * 50)
    print("Passphrases are easier to remember: 'Castle-Dragon-River-2024'")

    try:
        num_words = int(input("Number of words (3-8, default 4): ") or "4")
        if num_words < 3 or num_words > 8:
            num_words = 4
    except ValueError:
        num_words = 4

    separator = input("Word separator (-, _, space, default -): ") or "-"
    include_numbers = input("Include numbers? (Y/n): ").lower() != 'n'

    try:
        count = int(input("How many passphrases to generate? (1-10, default 3): ") or "3")
        if count < 1 or count > 10:
            count = 3
    except ValueError:
        count = 3

    print(f"\nGenerating {count} passphrases...\n")

    for i in range(count):
        passphrase = analyzer.generate_passphrase(
            num_words=num_words,
            separator=separator,
            include_numbers=include_numbers
        )

        # Analyze the passphrase
        analysis = analyzer.analyze_password(passphrase)

        print(f"Passphrase {i + 1}: {passphrase}")
        print(f"Strength: {analysis['strength']} ({analysis['score']}/100)")
        print(f"Length: {len(passphrase)} characters")
        print("-" * 50)


def generate_password_with_requirements(self, min_score=80, max_attempts=50):
    """Generate password that meets minimum strength requirements"""

    for attempt in range(max_attempts):
        password = self.generate_secure_password()
        analysis = self.analyze_password(password)

        if analysis['score'] >= min_score:
            return password, analysis

    # If we can't meet requirements, return best attempt
    return password, analysis


def load_custom_words(self, filename="custom_words.txt"):
    """Load custom words for passphrase generation"""
    try:
        with open(filename, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        return self.get_default_words()


def estimate_crack_time(self, password):
        """Estimate time to crack password"""
        entropy = self.calculate_entropy(password)

        # Assume 1 billion guesses per second
        guesses_per_second = 1_000_000_000
        total_combinations = 2 ** entropy
        seconds_to_crack = total_combinations / (2 * guesses_per_second)

        # Convert to human readable time
        if seconds_to_crack < 60:
            return f"{seconds_to_crack:.1f} seconds"
        elif seconds_to_crack < 3600:
            return f"{seconds_to_crack / 60:.1f} minutes"
        elif seconds_to_crack < 86400:
            return f"{seconds_to_crack / 3600:.1f} hours"
        elif seconds_to_crack < 31536000:
            return f"{seconds_to_crack / 86400:.1f} days"
        else:
            return f"{seconds_to_crack / 31536000:.1f} years"


def show_security_tips():
    """Display password security education"""
    tips = """
    PASSWORD SECURITY BEST PRACTICES:

    1. Length Matters: Use at least 12-16 characters
    2. Complexity: Mix uppercase, lowercase, numbers, and symbols
    3. Uniqueness: Use different passwords for each account
    4. Avoid Patterns: No keyboard walks, sequences, or personal info
    5. Use Passphrases: "Coffee$Morning#Walk2024" is stronger than "C@ff33"
    6. Enable 2FA: Add two-factor authentication when available
    7. Use Password Managers: Let tools generate and store strong passwords
    8. Regular Updates: Change passwords if there's a security breach

    COMMON ATTACK METHODS:
    • Dictionary attacks: Using common passwords
    • Brute force: Trying all possible combinations
    • Rainbow tables: Precomputed hash lookups
    • Social engineering: Guessing based on personal information

    Remember: A strong password is your first line of defense!
    """
    print(tips)


if __name__ == "__main__":
    main()