from flask import Flask, request, jsonify

app = Flask(__name__)

# In-memory store (demo only)
PUBLIC_KEYS = {}   # user_id -> {'p':..., 'g':..., 'pub':...}
INBOX = {}         # user_id -> [ {from, iv, ct, tag, aad} ]

@app.route('/register_key', methods=['POST'])
def register_key():
    data = request.get_json()
    user_id = data.get('user_id')
    p = data.get('p')
    g = data.get('g')
    pub = data.get('pub')
    if not user_id or not p or not g or not pub:
        return jsonify({'error': 'missing fields'}), 400
    PUBLIC_KEYS[user_id] = {'p': int(p), 'g': int(g), 'pub': int(pub)}
    INBOX.setdefault(user_id, [])
    return jsonify({'status': 'ok'})

@app.route('/get_key/<user_id>', methods=['GET'])
def get_key(user_id):
    entry = PUBLIC_KEYS.get(user_id)
    if not entry:
        return jsonify({'error': 'not found'}), 404
    return jsonify({'p': str(entry['p']), 'g': str(entry['g']), 'pub': str(entry['pub'])})

@app.route('/send_transaction', methods=['POST'])
def send_transaction():
    data = request.get_json()
    to = data.get('to')
    from_user = data.get('from')
    iv = data.get('iv')
    ct = data.get('ct')
    tag = data.get('tag')
    aad = data.get('aad')
    if to not in INBOX:
        return jsonify({'error': 'recipient not found'}), 404
    INBOX[to].append({'from': from_user, 'iv': iv, 'ct': ct, 'tag': tag, 'aad': aad})
    return jsonify({'status': 'queued'})

@app.route('/inbox/<user_id>', methods=['GET'])
def inbox(user_id):
    messages = INBOX.get(user_id, [])
    INBOX[user_id] = []
    return jsonify({'messages': messages})

if __name__ == '__main__':
    app.run(port=5000, debug=True)
