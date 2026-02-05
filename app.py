import streamlit as st
from password_checker import PasswordAnalyzer
import pandas as pd

# Page configuration
st.set_page_config(
    page_title="Password Security Analyzer",
    page_icon="🔒",
    layout="wide"
)


# Initialize analyzer
@st.cache_resource
def get_analyzer():
    return PasswordAnalyzer()


analyzer = get_analyzer()

# App title and description
st.title("🔒 Password Security Analyzer")
st.markdown("Analyze password strength and generate secure passwords")

# Sidebar navigation
page = st.sidebar.selectbox(
    "Choose a tool",
    ["Password Analyzer", "Password Generator", "Passphrase Generator", "Security Tips"]
)

# Page 1: Password Analyzer
if page == "Password Analyzer":
    st.header("Password Strength Analyzer")
    st.markdown("Enter a password to analyze its security. Your password is not stored or transmitted.")

    password = st.text_input("Enter password to analyze:", type="password", key="analyze_pwd")

    if st.button("Analyze Password", type="primary"):
        if password:
            results = analyzer.analyze_password(password)

            # Display score with color coding
            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric("Strength", results['strength'])
            with col2:
                st.metric("Score", f"{results['score']}/100")
            with col3:
                st.metric("Entropy", f"{results['entropy']:.1f} bits")

            # Progress bar for score
            st.progress(results['score'] / 100)

            # Security checks
            st.subheader("Security Checks")

            checks_data = {
                "Check": [
                    "Length (8+ chars)",
                    "Uppercase letters",
                    "Lowercase letters",
                    "Numbers",
                    "Special characters",
                    "No sequential numbers",
                    "No keyboard patterns",
                    "No repeated characters",
                    "Not common password"
                ],
                "Status": [
                    "✅ PASS" if results['length_ok'] else "❌ FAIL",
                    "✅ PASS" if results['complexity']['uppercase'] else "❌ FAIL",
                    "✅ PASS" if results['complexity']['lowercase'] else "❌ FAIL",
                    "✅ PASS" if results['complexity']['digits'] else "❌ FAIL",
                    "✅ PASS" if results['complexity']['special_chars'] else "❌ FAIL",
                    "✅ PASS" if not results['weak_patterns']['sequential_numbers'] else "❌ FAIL",
                    "✅ PASS" if not results['weak_patterns']['keyboard_patterns'] else "❌ FAIL",
                    "✅ PASS" if not results['weak_patterns']['repeated_chars'] else "❌ FAIL",
                    "✅ PASS" if not results['is_common'] else "❌ FAIL"
                ]
            }

            df = pd.DataFrame(checks_data)
            st.dataframe(df, use_container_width=True, hide_index=True)

            # Recommendations
            if results['score'] < 70:
                st.subheader("🔧 Recommendations")
                recommendations = []

                if not results['length_ok']:
                    recommendations.append("Use at least 8 characters (12+ recommended)")
                if not results['complexity']['uppercase']:
                    recommendations.append("Add uppercase letters (A-Z)")
                if not results['complexity']['lowercase']:
                    recommendations.append("Add lowercase letters (a-z)")
                if not results['complexity']['digits']:
                    recommendations.append("Add numbers (0-9)")
                if not results['complexity']['special_chars']:
                    recommendations.append("Add special characters (!@#$%^&*)")
                if results['weak_patterns']['sequential_numbers']:
                    recommendations.append("Avoid sequential numbers (123, 456, etc.)")
                if results['weak_patterns']['keyboard_patterns']:
                    recommendations.append("Avoid keyboard patterns (qwerty, asdf, etc.)")
                if results['is_common']:
                    recommendations.append("Avoid common passwords")

                for rec in recommendations:
                    st.warning(rec)
            else:
                st.success("✅ Great job! Your password meets security standards.")

            # Password hash (educational)
            with st.expander("🔐 Password Hash (SHA-256)"):
                st.code(results['hash'])
                st.caption("This is how your password would be stored securely in a database")
        else:
            st.error("Please enter a password to analyze")

# Page 2: Password Generator
elif page == "Password Generator":
    st.header("Secure Password Generator")
    st.markdown("Generate cryptographically secure passwords")

    col1, col2 = st.columns(2)

    with col1:
        length = st.slider("Password Length", 8, 32, 16)
        count = st.slider("Number of passwords", 1, 10, 5)

    with col2:
        include_upper = st.checkbox("Uppercase (A-Z)", value=True)
        include_lower = st.checkbox("Lowercase (a-z)", value=True)
        include_digits = st.checkbox("Numbers (0-9)", value=True)
        include_symbols = st.checkbox("Symbols (!@#$)", value=True)
        exclude_ambiguous = st.checkbox("Exclude ambiguous (0,O,1,l,I)", value=True)

    if st.button("Generate Passwords", type="primary"):
        st.subheader("Generated Passwords")

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

                analysis = analyzer.analyze_password(password)

                with st.container():
                    col1, col2, col3 = st.columns([3, 1, 1])
                    with col1:
                        st.code(password, language=None)
                    with col2:
                        st.caption(f"**{analysis['strength']}**")
                    with col3:
                        st.caption(f"**{analysis['score']}/100**")

            except ValueError as e:
                st.error(f"Error: {e}")
                break

# Page 3: Passphrase Generator
elif page == "Passphrase Generator":
    st.header("Passphrase Generator")
    st.markdown("Generate memorable passphrases like: `Castle-Dragon-River-2024`")

    col1, col2 = st.columns(2)

    with col1:
        num_words = st.slider("Number of words", 3, 8, 4)
        count = st.slider("Number of passphrases", 1, 10, 3)

    with col2:
        separator = st.selectbox("Separator", ["-", "_", " ", ".", ","])
        include_numbers = st.checkbox("Include numbers", value=True)

    if st.button("Generate Passphrases", type="primary"):
        st.subheader("Generated Passphrases")

        for i in range(count):
            passphrase = analyzer.generate_passphrase(
                num_words=num_words,
                separator=separator,
                include_numbers=include_numbers
            )

            analysis = analyzer.analyze_password(passphrase)

            with st.container():
                col1, col2, col3, col4 = st.columns([3, 1, 1, 1])
                with col1:
                    st.code(passphrase, language=None)
                with col2:
                    st.caption(f"**{analysis['strength']}**")
                with col3:
                    st.caption(f"**{analysis['score']}/100**")
                with col4:
                    st.caption(f"**{len(passphrase)} chars**")

# Page 4: Security Tips
elif page == "Security Tips":
    st.header("Password Security Best Practices")

    st.markdown("""
    ### 🎯 Key Principles

    1. **Length Matters Most**
       - Use at least 12-16 characters
       - Longer passwords are exponentially harder to crack

    2. **Complexity Counts**
       - Mix uppercase, lowercase, numbers, and symbols
       - Avoid predictable patterns

    3. **Uniqueness is Critical**
       - Use different passwords for each account
       - One breach shouldn't compromise everything

    4. **Avoid Common Mistakes**
       - No personal information (birthdays, names)
       - No dictionary words
       - No keyboard patterns (qwerty, 123456)

    5. **Use Passphrases**
       - "Coffee$Morning#Walk2024" beats "C@ff33"
       - Easier to remember, harder to crack

    ### 🛡️ Advanced Security

    - **Enable Two-Factor Authentication (2FA)** whenever possible
    - **Use a Password Manager** like Bitwarden, 1Password, or LastPass
    - **Update passwords** if there's been a security breach
    - **Never share passwords** via email or text
    - **Be wary of phishing** attempts asking for passwords

    ### ⚠️ Common Attack Methods

    | Attack Type | Description | Defense |
    |------------|-------------|---------|
    | Dictionary Attack | Trying common passwords | Use unique, complex passwords |
    | Brute Force | Trying all combinations | Use long passwords (16+ chars) |
    | Rainbow Tables | Precomputed hash lookups | Sites should use salted hashes |
    | Social Engineering | Guessing based on personal info | Avoid personal details in passwords |
    | Phishing | Tricking you into revealing passwords | Verify URLs, never click suspicious links |

    ### 📊 Password Entropy Explained

    Entropy measures password unpredictability in bits:
    - **< 28 bits**: Very Weak (crackable instantly)
    - **28-35 bits**: Weak (crackable in seconds)
    - **36-59 bits**: Fair (crackable in hours/days)
    - **60-127 bits**: Good (crackable in years)
    - **128+ bits**: Strong (practically uncrackable)

    A 16-character password with all character types has ~105 bits of entropy!
    """)

    # Interactive entropy calculator
    st.subheader("🧮 Entropy Calculator")
    test_password = st.text_input("Test a password:", type="password")

    if test_password:
        entropy = analyzer.calculate_entropy(test_password)
        st.metric("Password Entropy", f"{entropy:.1f} bits")

        if entropy < 28:
            st.error("Very Weak - Change immediately!")
        elif entropy < 36:
            st.warning("Weak - Needs improvement")
        elif entropy < 60:
            st.info("Fair - Consider strengthening")
        elif entropy < 128:
            st.success("Good - Meets security standards")
        else:
            st.success("Strong - Excellent password!")

# Footer
st.sidebar.markdown("---")
st.sidebar.markdown("### About")
st.sidebar.info("""
This tool analyzes password security and generates secure passwords.

**Features:**
- Password strength analysis
- Secure password generation
- Passphrase creation
- Security education

**Note:** Your passwords are never stored or transmitted.
""")
