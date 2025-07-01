# ZK-RSA Setup Verifier

A Zero-Knowledge Proof system that demonstrates how to prove knowledge of RSA prime factors without revealing the factors themselves.

## 🎯 Overview

This project implements a Zero-Knowledge Proof (ZKP) system for RSA setup verification. It allows a prover to demonstrate they know two prime numbers (p and q) that multiply to form an RSA modulus (n = p × q), without revealing the actual values of p or q.

## 🔍 What is Zero-Knowledge Proof?

Zero-Knowledge Proofs are cryptographic methods that allow one party (the prover) to prove to another party (the verifier) that they know a value, without revealing any information about the value itself.

In the context of RSA:
- **Traditional approach**: "Here are my primes p=61 and q=53, you can verify that 61×53=3233"
- **Zero-Knowledge approach**: "I can prove I know two primes that multiply to 3233, without telling you what they are"

## ✨ Features

- ✅ Prove knowledge of RSA prime factors without revealing them
- ✅ Verify the mathematical validity of the proof
- ✅ Support for multiple test cases
- ✅ Invalid input detection (p=1, q=1, p=q)
- ✅ Clean command-line interface
- ✅ Structured codebase with reusable components

## 📋 Prerequisites

- **Node.js** (v14 or higher)
- **Python** (v3.7 or higher)
- **Git** (for cloning the repository)

## 🚀 Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/zk-rsa-verifier.git
   cd zk-rsa-verifier
   ```

2. **Install Circom 2**
   ```bash
   npm install -g circom2
   ```

3. **Install SnarkJS**
   ```bash
   npm install -g snarkjs
   ```

4. **Verify installation**
   ```bash
   circom2 --version
   snarkjs --version
   ```

## 💻 Usage

### Quick Demo

Run the complete demonstration:
```bash
python zk_rsa_final.py
```


## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Note**: This project demonstrates the concept of zero-knowledge proofs applied to RSA. It uses small primes for demonstration purposes. Real RSA implementations use much larger primes (typically 1024-2048 bits each).
