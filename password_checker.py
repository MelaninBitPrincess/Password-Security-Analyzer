import re # noqa
import hashlib # noqa
import requests # noqa
import secrets # noqa
import string # noqa
import math # noqa

class PasswordAnalyzer:
    def __init__(self):
        self.common_passwords = self.load_common_passwords()

    def load_common_passwords(self):
        """Load common passwords from file"""
        try:
            with open('common_passwords.txt', 'r') as f:
                return set(line.strip().lower() for line in f)
        except FileNotFoundError:
            return set(['password', '123456', 'admin', 'welcome'])

    def check_length(self, password):
        """Check if password meets minimum length requirement"""
        return len(password) >= 8

    def check_complexity(self, password):
        """Check password complexity requirements"""
        checks = {
            'uppercase': bool(re.search(r'[A-Z]', password)),
            'lowercase': bool(re.search(r'[a-z]', password)),
            'digits': bool(re.search(r'\d', password)),
            'special_chars': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))
        }
        return checks

    def check_common_patterns(self, password):
        """Check for common weak patterns"""
        patterns = {
            'sequential_numbers': bool(re.search(r'123|234|345|456|567|678|789', password)),
            'keyboard_patterns': bool(re.search(r'qwerty|asdf|zxcv', password.lower())),
            'repeated_chars': bool(re.search(r'(.)\1{2,}', password))
        }
        return patterns

    def check_against_common_list(self, password):
        """Check if password is in common passwords list"""
        return password.lower() in self.common_passwords

    def calculate_entropy(self, password):
        """Calculate password entropy (simplified)"""
        charset_size = 0
        if re.search(r'[a-z]', password): charset_size += 26
        if re.search(r'[A-Z]', password): charset_size += 26
        if re.search(r'\d', password): charset_size += 10
        if re.search(r'[!@#$%^&*(),.?":{}|<>]', password): charset_size += 32

        if charset_size == 0: return 0
        import math
        return len(password) * math.log2(charset_size)

    def hash_password(self, password):
        """Demonstrate password hashing"""
        return hashlib.sha256(password.encode()).hexdigest()

    def analyze_password(self, password):
        """Comprehensive password analysis"""
        results = {
            'password': password,
            'length_ok': self.check_length(password),
            'complexity': self.check_complexity(password),
            'weak_patterns': self.check_common_patterns(password),
            'is_common': self.check_against_common_list(password),
            'entropy': self.calculate_entropy(password),
            'hash': self.hash_password(password)
        }

        # Calculate overall score
        score = 0
        if results['length_ok']: score += 20
        score += sum(results['complexity'].values()) * 15
        if not any(results['weak_patterns'].values()): score += 20
        if not results['is_common']: score += 20

        results['score'] = min(score, 100)
        results['strength'] = self.get_strength_rating(results['score'])

        return results

    def get_strength_rating(self, score):
        """Convert score to strength rating"""
        if score < 30:
            return "Very Weak"
        elif score < 50:
            return "Weak"
        elif score < 70:
            return "Fair"
        elif score < 90:
            return "Good"
        else:
            return "Strong"

    def generate_secure_password(self, length=16, include_uppercase=True,
                                 include_lowercase=True, include_digits=True,
                                 include_symbols=True, exclude_ambiguous=True):
        """Generate a cryptographically secure password"""

        # Build character set
        charset = ""

        if include_lowercase:
            charset += string.ascii_lowercase
        if include_uppercase:
            charset += string.ascii_uppercase
        if include_digits:
            charset += string.digits
        if include_symbols:
            charset += "!@#$%^&*()_+-=[]{}|;:,.<>?"

        # Remove ambiguous characters if requested
        if exclude_ambiguous:
            ambiguous = "0O1lI|`"
            charset = ''.join(c for c in charset if c not in ambiguous)

        if not charset:
            raise ValueError("At least one character type must be selected")

        # Ensure password has at least one character from each selected type
        password = []

        if include_lowercase:
            password.append(secrets.choice(string.ascii_lowercase))
        if include_uppercase:
            password.append(secrets.choice(string.ascii_uppercase))
        if include_digits:
            password.append(secrets.choice(string.digits))
        if include_symbols:
            password.append(secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?"))

        # Fill the rest randomly
        for _ in range(length - len(password)):
            password.append(secrets.choice(charset))

        # Shuffle to avoid predictable patterns
        secrets.SystemRandom().shuffle(password)

        return ''.join(password)

    def generate_passphrase(self, num_words=4, separator="-", include_numbers=True):
        """Generate a memorable passphrase"""

        # Common words list (you could expand this or load from a file)
        words = [
            "apple", "bridge", "castle", "dream", "eagle", "forest", "guitar", "happy",
            "island", "jungle", "kitchen", "library", "mountain", "notebook", "ocean",
            "piano", "quiet", "rainbow", "sunset", "travel", "umbrella", "village",
            "wizard", "yellow", "zebra", "coffee", "dragon", "flower", "magic", "puzzle",
            "rocket", "silver", "thunder", "wonder", "crystal", "garden", "harmony",
            "journey", "mystery", "phoenix", "storm", "treasure", "victory", "wisdom"
        ]

        # Select random words
        selected_words = [secrets.choice(words).capitalize() for _ in range(num_words)]

        # Add numbers if requested
        if include_numbers:
            # Add a random number between 10-999
            number = secrets.randbelow(990) + 10
            selected_words.append(str(number))

        return separator.join(selected_words)

    def generate_multiple_passwords(self, count=5, length=16):
        """Generate multiple password options"""
        passwords = []
        for _ in range(count):
            password = self.generate_secure_password(length=length)
            analysis = self.analyze_password(password)
            passwords.append({
                'password': password,
                'strength': analysis['strength'],
                'score': analysis['score']
            })
        return passwords