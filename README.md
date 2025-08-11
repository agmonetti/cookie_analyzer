# Cookie Analyzer

## Brief Description
Cookie Analyzer is a browser extension that analyzes, classifies, and helps you manage cookies from websites you visit. It evaluates the risk level of each cookie for your privacy and security, identifying tracking cookies, fingerprinting, and insecure authentication.

## Main Features

- **Automatic Analysis**: Evaluates all cookies from the current site in real-time
- **Risk Classification**: Categorizes cookies as Critical, High, Medium, or Safe
- **Advanced Detection**: Identifies tracking cookies, fingerprinting, and insecure configurations
- **Detailed Explanation**: Shows specific reasons why a cookie is considered risky
- **Simplified Management**: Allows you to delete individual cookies, suspicious ones, or all site cookies

## How It Works

The extension analyzes each cookie based on multiple criteria:

1. **Database of known cookies** for tracking and analytics
2. **Name and value patterns** indicating authentication or tracking
3. **Security configuration** (HttpOnly, Secure, SameSite)
4. **Entropy analysis** to detect random/encrypted values
5. **Domain verification** to identify third-party cookies

## Risk Levels

- 🟢 **Safe (0-29%)**: Well-configured functional cookies
- 🔵 **Medium (30-49%)**: Some level of privacy risk
- 🟡 **High (50-69%)**: Considerable risk, usually tracking
- 🔴 **Critical (70-100%)**: High risk, possible security issues

## Limitations

- Analysis is heuristic, not infallible
- Should be complemented with other privacy tools
- Doesn't work on internal browser pages
- Cannot see HttpOnly cookies from JavaScript

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)

---
