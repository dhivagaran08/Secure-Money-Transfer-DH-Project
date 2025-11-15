import requests, json
from utils.crypto_utils import generate_dh_params, dh_generate_private_key, dh_compute_public, dh_compute_shared, derive_aes_key, aes_gcm_encrypt, aes_gcm_decrypt

SERVER = 'http://127.0.0.1:5000'

# Edit to set your user_id and recipient
user_id = 'alice'
recipient_id = 'bob'

p, g = generate_dh_params()
priv = dh_generate_private_key(p)
pub = dh_compute_public(g, priv, p)

# Register with server
resp = requests.post(f"{SERVER}/register_key", json={'user_id': user_id, 'p': str(p), 'g': str(g), 'pub': str(pub)})
print('register:', resp.json())

# Try to fetch recipient key
resp = requests.get(f"{SERVER}/get_key/{recipient_id}")
if resp.status_code != 200:
    print('Recipient key not found — make sure recipient registered.'); exit(1)
rec = resp.json()
rec_pub = int(rec['pub'])
rec_p = int(rec['p'])

# Compute shared secret and AES key
shared = dh_compute_shared(rec_pub, priv, rec_p)
aes_key = derive_aes_key(shared)

# Build transaction
transaction = {'from': user_id, 'to': recipient_id, 'amount': 2500, 'timestamp': '2025-11-14'}
pt = json.dumps(transaction).encode()
enc = aes_gcm_encrypt(aes_key, pt)

# Send encrypted transaction
send_payload = {'to': recipient_id, 'from': user_id, 'iv': enc['iv'].hex(), 'ct': enc['ct'].hex(), 'tag': enc['tag'].hex(), 'aad': ''}
resp = requests.post(f"{SERVER}/send_transaction", json=send_payload)
print('send response:', resp.json())

# Recipient: fetch inbox and decrypt (example flow)
resp = requests.get(f"{SERVER}/inbox/{recipient_id}")
print('recipient inbox response:', resp.json())
