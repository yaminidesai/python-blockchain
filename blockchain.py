import hashlib
import json
import time
from flask import Flask, jsonify, request
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from typing import List

# ============= MERKLE TREE =============
class MerkleTree:
    def __init__(self, transactions):
        self.transactions = transactions
        self.tree = []
        self.root = self.build_tree()
    
    @staticmethod
    def hash_data(data):
        return hashlib.sha256(str(data).encode()).hexdigest()
    
    def build_tree(self):
        if not self.transactions:
            return self.hash_data("empty")
        
        current_level = [self.hash_data(tx.get_data()) for tx in self.transactions]
        self.tree.append(current_level)
        
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                if i + 1 < len(current_level):
                    combined = current_level[i] + current_level[i + 1]
                    next_level.append(self.hash_data(combined))
                else:
                    combined = current_level[i] + current_level[i]
                    next_level.append(self.hash_data(combined))
            self.tree.append(next_level)
            current_level = next_level
        
        return current_level[0]

# ============= WALLET =============
class Wallet:
    def __init__(self, name):
        self.name = name
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        self.address = self.get_public_key_string()
    
    def get_public_key_string(self):
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return pem.decode('utf-8')
    
    def sign_transaction(self, transaction_data):
        message = json.dumps(transaction_data, sort_keys=True).encode()
        signature = self.private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature.hex()
    
    @staticmethod
    def verify_signature(public_key_string, transaction_data, signature_hex):
        try:
            public_key = serialization.load_pem_public_key(
                public_key_string.encode(),
                backend=default_backend()
            )
            message = json.dumps(transaction_data, sort_keys=True).encode()
            signature = bytes.fromhex(signature_hex)
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False

# ============= TRANSACTION =============
class Transaction:
    def __init__(self, sender_address, recipient_address, amount, fee=0, sender_wallet=None):
        self.sender = sender_address
        self.recipient = recipient_address
        self.amount = amount
        self.fee = fee
        self.timestamp = time.time()
        self.signature = None
        
        if sender_wallet:
            self.sign(sender_wallet)
    
    def get_data(self):
        return {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": self.amount,
            "fee": self.fee,
            "timestamp": self.timestamp
        }
    
    def sign(self, wallet):
        if wallet.address != self.sender:
            raise ValueError("Cannot sign transaction from different wallet!")
        self.signature = wallet.sign_transaction(self.get_data())
    
    def is_valid(self):
        if self.sender == "MINING_REWARD":
            return True
        if not self.signature:
            return False
        return Wallet.verify_signature(self.sender, self.get_data(), self.signature)
    
    def get_total_cost(self):
        return self.amount + self.fee
    
    def to_dict(self):
        return {
            "sender": self.sender[:40] + "..." if len(self.sender) > 40 else self.sender,
            "recipient": self.recipient[:40] + "..." if len(self.recipient) > 40 else self.recipient,
            "amount": self.amount,
            "fee": self.fee,
            "timestamp": self.timestamp,
            "signed": self.signature is not None
        }

# ============= BLOCK =============
class Block:
    def __init__(self, index, transactions, previous_hash):
        self.index = index
        self.timestamp = time.time()
        self.transactions = transactions
        self.previous_hash = previous_hash
        self.merkle_tree = MerkleTree(transactions)
        self.merkle_root = self.merkle_tree.root
        self.nonce = 0
        self.hash = self.calculate_hash()
    
    def calculate_hash(self):
        block_data = {
            "index": self.index,
            "timestamp": self.timestamp,
            "merkle_root": self.merkle_root,
            "previous_hash": self.previous_hash,
            "nonce": self.nonce
        }
        return hashlib.sha256(json.dumps(block_data, sort_keys=True).encode()).hexdigest()
    
    def mine_block(self, difficulty):
        target = "0" * difficulty
        while self.hash[:difficulty] != target:
            self.nonce += 1
            self.hash = self.calculate_hash()
    
    def has_valid_transactions(self):
        return all(tx.is_valid() for tx in self.transactions)
    
    def get_total_fees(self):
        return sum(tx.fee for tx in self.transactions if tx.sender != "MINING_REWARD")
    
    def to_dict(self):
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "transactions": [tx.to_dict() for tx in self.transactions],
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "hash": self.hash,
            "nonce": self.nonce
        }

# ============= BLOCKCHAIN =============
class Blockchain:
    def __init__(self, difficulty=2):
        self.chain = []
        self.difficulty = difficulty
        self.pending_transactions = []
        self.mining_reward = 10
        self.create_genesis_block()
    
    def create_genesis_block(self):
        genesis = Block(0, [], "0")
        genesis.mine_block(self.difficulty)
        self.chain.append(genesis)
    
    def get_latest_block(self):
        return self.chain[-1]
    
    def add_transaction(self, transaction):
        if not transaction.is_valid():
            return {"success": False, "message": "Invalid transaction"}
        
        if transaction.sender != "MINING_REWARD":
            balance = self.get_balance(transaction.sender)
            total_cost = transaction.get_total_cost()
            if balance < total_cost:
                return {"success": False, "message": f"Insufficient funds. Balance: {balance}, Need: {total_cost}"}
        
        self.pending_transactions.append(transaction)
        return {"success": True, "message": "Transaction added to pending pool"}
    
    def mine_pending_transactions(self, miner_address):
        total_fees = sum(tx.fee for tx in self.pending_transactions if tx.sender != "MINING_REWARD")
        total_reward = self.mining_reward + total_fees
        reward_tx = Transaction("MINING_REWARD", miner_address, total_reward)
        self.pending_transactions.append(reward_tx)
        
        block = Block(len(self.chain), self.pending_transactions, self.get_latest_block().hash)
        block.mine_block(self.difficulty)
        
        if block.has_valid_transactions():
            self.chain.append(block)
            self.pending_transactions = []
            return {"success": True, "message": f"Block mined! Reward: {total_reward} coins"}
        else:
            return {"success": False, "message": "Block rejected - invalid transactions"}
    
    def get_balance(self, address):
        balance = 0
        for block in self.chain:
            for tx in block.transactions:
                if tx.recipient == address:
                    balance += tx.amount
                if tx.sender == address:
                    balance -= tx.amount + tx.fee
        return balance
    
    def is_chain_valid(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i-1]
            
            if current.hash != current.calculate_hash():
                return False
            if current.previous_hash != previous.hash:
                return False
            if not current.has_valid_transactions():
                return False
            
            merkle_check = MerkleTree(current.transactions)
            if merkle_check.root != current.merkle_root:
                return False
        return True
    
    def get_stats(self):
        total_blocks = len(self.chain)
        total_txs = sum(len(block.transactions) for block in self.chain)
        total_fees = sum(block.get_total_fees() for block in self.chain)
        
        return {
            "total_blocks": total_blocks,
            "total_transactions": total_txs,
            "total_fees_collected": total_fees,
            "difficulty": self.difficulty,
            "pending_transactions": len(self.pending_transactions),
            "chain_valid": self.is_chain_valid()
        }

# ============= FLASK API =============
app = Flask(__name__)
blockchain = Blockchain(difficulty=2)

# Create some demo wallets
alice = Wallet("Alice")
bob = Wallet("Bob")
charlie = Wallet("Charlie")

wallets = {
    "alice": alice,
    "bob": bob,
    "charlie": charlie
}

@app.route('/')
def home():
    return jsonify({
        "message": "🔗 Blockchain API",
        "endpoints": {
            "GET /blockchain": "View entire blockchain",
            "GET /blockchain/stats": "Get blockchain statistics",
            "GET /blockchain/validate": "Validate blockchain",
            "GET /block/<index>": "Get specific block",
            "GET /balance/<wallet_name>": "Get wallet balance",
            "POST /transaction": "Create new transaction",
            "POST /mine": "Mine pending transactions",
            "GET /pending": "View pending transactions"
        }
    })

@app.route('/blockchain', methods=['GET'])
def get_blockchain():
    return jsonify({
        "chain": [block.to_dict() for block in blockchain.chain],
        "length": len(blockchain.chain)
    })

@app.route('/blockchain/stats', methods=['GET'])
def get_stats():
    return jsonify(blockchain.get_stats())

@app.route('/blockchain/validate', methods=['GET'])
def validate_chain():
    return jsonify({
        "valid": blockchain.is_chain_valid(),
        "message": "Blockchain is valid ✓" if blockchain.is_chain_valid() else "Blockchain is invalid ✗"
    })

@app.route('/block/<int:index>', methods=['GET'])
def get_block(index):
    if index < 0 or index >= len(blockchain.chain):
        return jsonify({"error": "Block not found"}), 404
    return jsonify(blockchain.chain[index].to_dict())

@app.route('/balance/<wallet_name>', methods=['GET'])
def get_balance(wallet_name):
    if wallet_name not in wallets:
        return jsonify({"error": "Wallet not found"}), 404
    
    wallet = wallets[wallet_name]
    balance = blockchain.get_balance(wallet.address)
    return jsonify({
        "wallet": wallet_name,
        "balance": balance
    })

@app.route('/transaction', methods=['POST'])
def create_transaction():
    data = request.get_json()
    
    required = ['sender', 'recipient', 'amount']
    if not all(k in data for k in required):
        return jsonify({"error": "Missing required fields"}), 400
    
    sender_name = data['sender']
    recipient_name = data['recipient']
    
    if sender_name not in wallets or recipient_name not in wallets:
        return jsonify({"error": "Wallet not found"}), 404
    
    sender_wallet = wallets[sender_name]
    recipient_wallet = wallets[recipient_name]
    amount = data['amount']
    fee = data.get('fee', 0)
    
    tx = Transaction(sender_wallet.address, recipient_wallet.address, amount, fee, sender_wallet)
    result = blockchain.add_transaction(tx)
    
    return jsonify(result)

@app.route('/mine', methods=['POST'])
def mine():
    data = request.get_json()
    
    if 'miner' not in data:
        return jsonify({"error": "Miner wallet required"}), 400
    
    miner_name = data['miner']
    if miner_name not in wallets:
        return jsonify({"error": "Wallet not found"}), 404
    
    miner_wallet = wallets[miner_name]
    result = blockchain.mine_pending_transactions(miner_wallet.address)
    
    return jsonify(result)

@app.route('/pending', methods=['GET'])
def get_pending():
    return jsonify({
        "pending_transactions": [tx.to_dict() for tx in blockchain.pending_transactions],
        "count": len(blockchain.pending_transactions)
    })

if __name__ == '__main__':
    print("\n" + "="*70)
    print("🚀 BLOCKCHAIN API SERVER")
    print("="*70)
    print("\n📝 Available wallets: alice, bob, charlie")
    print("\n🌐 Server starting at http://127.0.0.1:5000")
    print("\n💡 Try these commands in another terminal:")
    print("\n   # View blockchain")
    print("   curl http://127.0.0.1:5000/blockchain")
    print("\n   # Get stats")
    print("   curl http://127.0.0.1:5000/blockchain/stats")
    print("\n   # Check Alice's balance")
    print("   curl http://127.0.0.1:5000/balance/alice")
    print("\n   # Create transaction")
    print('   curl -X POST http://127.0.0.1:5000/transaction -H "Content-Type: application/json" -d \'{"sender": "alice", "recipient": "bob", "amount": 5, "fee": 1}\'')
    print("\n   # Mine block")
    print('   curl -X POST http://127.0.0.1:5000/mine -H "Content-Type: application/json" -d \'{"miner": "bob"}\'')
    print("\n" + "="*70 + "\n")
    
    app.run(debug=True, port=5000)