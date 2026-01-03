# 🔗 Python Blockchain Implementation

A fully functional blockchain implementation in Python featuring digital signatures, transaction fees, Merkle trees, and a complete REST API.

## 🌟 Features

- **⛏️ Proof of Work Mining** - SHA-256 based mining with adjustable difficulty
- **🔐 Digital Signatures** - RSA-2048 signing for transaction security
- **💰 Transaction Fees** - Economic model with mining rewards
- **🌳 Merkle Trees** - Efficient transaction verification (Bitcoin SPV)
- **🌐 REST API** - Complete HTTP API for blockchain interaction
- **💾 Persistence** - Save/load blockchain to disk

## 🚀 Quick Start

### Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/python-blockchain.git
cd python-blockchain

# Install dependencies
pip3 install -r requirements.txt

# Run the blockchain API
python3 blockchain.py
```

The API server will start at `http://127.0.0.1:5000`

### Quick Test
```bash
# In a new terminal

# Check API status
curl http://127.0.0.1:5000/

# Mine first block (Alice gets coins)
curl -X POST http://127.0.0.1:5000/mine \
  -H "Content-Type: application/json" \
  -d '{"miner": "alice"}'

# Check Alice's balance
curl http://127.0.0.1:5000/balance/alice

# Create a transaction
curl -X POST http://127.0.0.1:5000/transaction \
  -H "Content-Type: application/json" \
  -d '{"sender": "alice", "recipient": "bob", "amount": 5, "fee": 1}'

# Mine the transaction
curl -X POST http://127.0.0.1:5000/mine \
  -H "Content-Type: application/json" \
  -d '{"miner": "bob"}'
```

## 📚 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | API information |
| `/blockchain` | GET | View entire blockchain |
| `/blockchain/stats` | GET | Blockchain statistics |
| `/balance/:wallet` | GET | Check wallet balance |
| `/transaction` | POST | Create transaction |
| `/mine` | POST | Mine pending transactions |
| `/pending` | GET | View pending transactions |
| `/save` | POST | Save blockchain to file |

## 🏗️ Architecture
```
Blockchain
├── Block[]
│   ├── Transaction[] (with RSA signatures)
│   └── MerkleTree (for verification)
└── Wallet[] (RSA key pairs)
```

## 🔐 Security Features

- **Digital Signatures**: RSA-2048 with PSS padding
- **Hashing**: SHA-256 for all cryptographic operations
- **Proof of Work**: Adjustable difficulty consensus
- **Merkle Trees**: Efficient transaction verification
- **Tamper Detection**: Any modification invalidates the chain

## 🧪 Testing
```bash
# Test the blockchain
python3 blockchain.py

# In another terminal, run API tests
curl http://127.0.0.1:5000/blockchain/stats
```

## 📊 Performance

- **Difficulty 2**: ~0.01s per block
- **Difficulty 3**: ~0.1s per block  
- **Difficulty 4**: ~0.5s per block
- **Signature Verification**: <1ms per transaction

## 🎓 What This Demonstrates

This project shows understanding of:

✅ Blockchain fundamentals (blocks, chains, mining)  
✅ Cryptography (RSA signatures, SHA-256 hashing)  
✅ Proof of Work consensus  
✅ Transaction processing and validation  
✅ Balance tracking and fee economics  
✅ Merkle tree data structures  
✅ REST API development  

## 🛠️ Built With

- **Python 3.8+** - Core language
- **Flask** - Web framework for REST API
- **cryptography** - RSA signatures and key management
- **hashlib** - SHA-256 hashing

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

## 👤 Author

**Your Name**

- GitHub: [@yourusername](https://github.com/yourusername)
- LinkedIn: [Your Profile](https://linkedin.com/in/yourprofile)
- Email: your.email@example.com

## 🙏 Acknowledgments

- Bitcoin Whitepaper by Satoshi Nakamoto
- Inspired by Bitcoin and Ethereum implementations
- Built for educational purposes

---

**⭐ If you found this helpful for learning blockchain, please star it!**